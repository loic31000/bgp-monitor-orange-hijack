"""Scénarios de bout en bout avec des sources simulées (aucun appel réseau)."""

from __future__ import annotations

from typing import Any

import pytest

from bgpmon.alerts import AlertDispatcher
from bgpmon.config import AlertSettings, Config
from bgpmon.models import Route
from bgpmon.monitor import Monitor
from bgpmon.sources import SourceError
from bgpmon.sources.irr import IrrFetch, parse_rpsl
from bgpmon.sources.ripestat import RoutingStatus, RpkiResult
from bgpmon.sources.ris_live import parse_ris_message
from bgpmon.state import State
from tests.conftest import ASN_TARGET, ORANGE_TARGET, load_json, load_text, make_config

ORANGE_MS = [
    Route("90.98.0.0/16", "192.0.2.1", (6939, 5511, 3215), "ripestat", "rrc00"),
    Route("90.99.0.0/16", "192.0.2.1", (6939, 5511, 3215), "ripestat", "rrc00"),
]
HIJACK = Route("90.98.0.0/15", "192.0.2.1", (6939, 29802, 22541, 41128), "ripestat", "rrc00")


def origin(route: Route) -> int:
    last = route.as_path[-1]
    assert isinstance(last, int)
    return last


class FakeRipeStat:
    def __init__(self) -> None:
        self.fail = False
        self.routes: list[Route] = list(ORANGE_MS)
        self.seeing = 160
        self.prefixes: dict[int, set[str]] = {41128: set()}
        self.neighbours: dict[int, dict[int, str]] = {41128: {}}
        self.rpki: dict[tuple[str, int], RpkiResult] = {
            ("90.98.0.0/16", 3215): RpkiResult("valid", [{"origin": "3215"}]),
            ("90.99.0.0/16", 3215): RpkiResult("valid", [{"origin": "3215"}]),
        }

    def _check(self) -> None:
        if self.fail:
            raise SourceError("RIPEstat routing-status injoignable : HTTP 503")

    def routing_status(self, prefix: str) -> RoutingStatus:
        self._check()
        ms = [(r.prefix, origin(r)) for r in self.routes if r.prefix != prefix]
        exact = [origin(r) for r in self.routes if r.prefix == prefix]
        return RoutingStatus(
            prefix, origins=exact, more_specifics=ms, peers_seeing=self.seeing, total_peers=165
        )

    def bgp_state(self, prefix: str) -> list[Route]:
        self._check()
        return [r for r in self.routes if r.prefix == prefix]

    def prefix_routing_consistency(self, prefix: str) -> list[dict[str, Any]]:
        return []

    def rpki_validation(self, asn: int, prefix: str) -> RpkiResult:
        return self.rpki.get((prefix, asn), RpkiResult("unknown"))

    def announced_prefixes(self, asn: int, window_hours: int) -> set[str]:
        self._check()
        return set(self.prefixes.get(asn, set()))

    def asn_neighbours(self, asn: int) -> dict[int, str]:
        return dict(self.neighbours.get(asn, {}))

    def close(self) -> None:
        pass


class FakeIrr:
    def __init__(self) -> None:
        self.text = load_text("irr", "altdb_90_98_15_v1.txt")

    def fetch(self, target: Any) -> IrrFetch:
        objs = {o.object_id: o.to_dict() for o in parse_rpsl(self.text, "ALTDB")}
        return IrrFetch(objects={"ALTDB": objs})


class Recorder:
    name = "recorder"
    min_severity = "info"

    def __init__(self) -> None:
        self.events: list[Any] = []

    def send(self, ev: Any) -> None:
        self.events.append(ev)


@pytest.fixture
def env(state: State) -> tuple[Monitor, FakeRipeStat, Recorder, Config]:
    cfg = make_config([ORANGE_TARGET, ASN_TARGET])
    fake = FakeRipeStat()
    rec = Recorder()
    dispatcher = AlertDispatcher([rec], AlertSettings(), state)
    monitor = Monitor(cfg, state, fake, FakeIrr(), dispatcher)  # type: ignore[arg-type]
    return monitor, fake, rec, cfg


def test_clean_state_is_ok_and_silent(env: Any) -> None:
    monitor, _, rec, _ = env
    monitor.run_cycle(include_irr=True)
    assert monitor.refresh_all() == {"90.98.0.0/15": "OK", "AS41128": "OK"}
    assert rec.events == []


def test_hijack_raises_once_then_resolves(env: Any) -> None:
    monitor, fake, rec, _ = env
    monitor.run_cycle(include_irr=False)
    fake.routes.append(HIJACK)
    monitor.run_cycle(include_irr=False)
    states = monitor.refresh_all()
    assert states["90.98.0.0/15"] == "ALERT"
    types = sorted(e.type for e in rec.events)
    assert types == ["ORIGIN_FORBIDDEN", "PATH_FORBIDDEN_ASN", "PATH_FORBIDDEN_ASN", "RPKI_UNKNOWN"]
    # Cycles suivants : pas de nouvelle alerte tant que rien ne change.
    monitor.run_cycle(include_irr=False)
    assert len(rec.events) == 4
    fake.routes.remove(HIJACK)
    monitor.run_cycle(include_irr=False)
    assert monitor.refresh_all()["90.98.0.0/15"] == "OK"
    assert sorted(e.phase for e in rec.events[4:]) == ["resolved"] * 4


def test_source_error_gives_unknown_and_never_resolves(env: Any) -> None:
    monitor, fake, rec, cfg = env
    fake.routes.append(HIJACK)
    monitor.run_cycle(include_irr=False)
    raised = len(rec.events)
    fake.fail = True
    fake.routes.remove(HIJACK)
    for _ in range(cfg.settings.source_error_cycles):
        monitor.run_cycle(include_irr=False)
    # L'erreur ne résout pas la condition : la cible reste en alerte.
    assert monitor.refresh_all()["90.98.0.0/15"] == "ALERT"
    new = rec.events[raised:]
    assert {e.type for e in new} == {"SOURCE_ERROR"}
    assert all(e.phase == "raised" for e in new)


def test_source_error_without_prior_data_is_unknown(state: State) -> None:
    cfg = make_config([ORANGE_TARGET])
    fake = FakeRipeStat()
    fake.fail = True
    ripestat: Any = fake
    monitor = Monitor(cfg, state, ripestat, None, AlertDispatcher([], AlertSettings(), state))
    monitor.run_cycle(include_irr=False)
    assert monitor.refresh_all() == {"90.98.0.0/15": "UNKNOWN"}


def test_no_route_at_all_is_unknown_not_clean(env: Any) -> None:
    monitor, fake, _, _ = env
    fake.routes = []
    monitor.run_cycle(include_irr=False)
    assert monitor.refresh_all()["90.98.0.0/15"] == "UNKNOWN"


def test_visibility_drop_and_restore(env: Any) -> None:
    monitor, fake, rec, _ = env
    monitor.run_cycle(include_irr=False)
    fake.seeing = 40
    monitor.run_cycle(include_irr=False)
    fake.seeing = 158
    monitor.run_cycle(include_irr=False)
    assert [e.type for e in rec.events] == ["VISIBILITY_DROP", "VISIBILITY_RESTORED"]


def test_ris_live_hijack_and_withdrawal(env: Any) -> None:
    monitor, _, rec, _ = env
    monitor.run_cycle(include_irr=False)
    for upd in parse_ris_message(load_json("ris_live", "hijack_exact_41128.json")):
        monitor.handle_live_update(upd)
    assert monitor.state.target_states()["90.98.0.0/15"]["state"] == "ALERT"
    assert {e.source for e in rec.events} == {"ris_live"}
    # Une annonce non pertinente n'est pas stockée.
    for upd in parse_ris_message(load_json("ris_live", "mixed_prefixes.json")):
        monitor.handle_live_update(upd)
    assert set(monitor.state.rib_prefixes()) == {"90.98.0.0/15", "90.98.0.0/16"}
    before = len(rec.events)
    for upd in parse_ris_message(load_json("ris_live", "withdraw_exact.json")):
        monitor.handle_live_update(upd)
    resolved = rec.events[before:]
    assert resolved and all(e.phase == "resolved" for e in resolved)
    assert monitor.state.target_states()["90.98.0.0/15"]["state"] == "OK"


def test_ris_live_two_peers_withdraw_one(env: Any) -> None:
    monitor, _, rec, _ = env
    for name in ("hijack_exact_41128.json", "hijack_exact_41128_peer2.json", "withdraw_exact.json"):
        for upd in parse_ris_message(load_json("ris_live", name)):
            monitor.handle_live_update(upd)
    # Un peer voit encore la route : rien n'est résolu.
    assert all(e.phase == "raised" for e in rec.events)
    for upd in parse_ris_message(load_json("ris_live", "withdraw_exact_peer2.json")):
        monitor.handle_live_update(upd)
    assert any(e.phase == "resolved" for e in rec.events)


def test_ris_live_new_prefix_for_watched_asn(env: Any) -> None:
    monitor, fake, rec, _ = env
    monitor.run_cycle(include_irr=False)  # référence : AS41128 n'annonce rien
    for upd in parse_ris_message(load_json("ris_live", "asn_origin_41128.json")):
        monitor.handle_live_update(upd)
    assert [(e.type, e.prefix) for e in rec.events] == [("ASN_NEW_PREFIX", "203.0.113.0/24")]
    assert monitor.state.target_states()["AS41128"]["state"] == "ALERT"
    # Le passage RIPEstat suivant voit le même préfixe : pas de doublon.
    fake.prefixes[41128] = {"203.0.113.0/24"}
    monitor.run_cycle(include_irr=False)
    assert len(rec.events) == 1


def test_asn_neighbour_change(env: Any) -> None:
    monitor, fake, rec, _ = env
    monitor.run_cycle(include_irr=False)
    # Les voisins « uncertain » sont ignorés par défaut (neighbour_types).
    fake.neighbours[41128] = {22541: "left", 64500: "uncertain"}
    monitor.run_cycle(include_irr=False)
    assert [(e.type, e.severity) for e in rec.events] == [("ASN_NEW_NEIGHBOUR", "high")]


def test_learned_upstream_change(env: Any) -> None:
    monitor, fake, rec, _ = env
    monitor.run_cycle(include_irr=False)
    fake.routes[1] = Route("90.99.0.0/16", "192.0.2.1", (6939, 199524, 3215), "ripestat")
    monitor.run_cycle(include_irr=False)
    assert [e.type for e in rec.events] == ["PATH_UPSTREAM_CHANGE"]


def test_irr_baseline_then_diff(env: Any) -> None:
    monitor, _, rec, _ = env
    monitor.run_cycle(include_irr=True)
    assert rec.events == []
    monitor.irr.text = load_text("irr", "altdb_90_98_15_v2.txt")
    monitor.run_cycle(include_irr=True)
    types = sorted({e.type for e in rec.events})
    assert types == ["IRR_OBJECT_CREATED", "IRR_OBJECT_DELETED", "IRR_OBJECT_MODIFIED"]


def test_ris_live_disconnections_raise_global_source_error(env: Any) -> None:
    monitor, _, rec, cfg = env
    for _ in range(cfg.settings.source_error_cycles):
        monitor.handle_live_status("disconnected", "timeout")
    assert [e.type for e in rec.events] == ["SOURCE_ERROR"]
    monitor.handle_live_status("connected", None)
    assert rec.events[-1].phase == "resolved"


def test_expect_silent_target(state: State) -> None:
    silent = {
        "label": "198.193.12.0/24",
        "type": "prefix",
        "resource": "198.193.12.0/24",
        "expect_silent": True,
        "forbidden_origins": [2702],
        "severity": "high",
    }
    cfg = make_config([silent])
    fake = FakeRipeStat()
    fake.routes = []
    rec = Recorder()
    ripestat: Any = fake
    monitor = Monitor(cfg, state, ripestat, None, AlertDispatcher([rec], AlertSettings(), state))
    monitor.run_cycle(include_irr=False)
    states = monitor.refresh_all()
    assert states == {"198.193.12.0/24": "OK"}
    assert state.target_states()["198.193.12.0/24"]["reason"].startswith("OK-silencieux")
    # Réapparition : alerte immédiate via RIS Live, puis résolution au retrait.
    msg = load_json("ris_live", "asn_origin_41128.json")
    msg["data"]["announcements"][0]["prefixes"] = ["198.193.12.0/24"]
    msg["data"]["path"] = [6939, 2702]
    for upd in parse_ris_message(msg):
        monitor.handle_live_update(upd)
    assert {e.type for e in rec.events} == {"SILENCE_BROKEN", "ORIGIN_FORBIDDEN"}
    assert state.target_states()["198.193.12.0/24"]["state"] == "ALERT"
    msg["data"]["announcements"] = []
    msg["data"]["withdrawals"] = ["198.193.12.0/24"]
    for upd in parse_ris_message(msg):
        monitor.handle_live_update(upd)
    assert state.target_states()["198.193.12.0/24"]["state"] == "OK"
