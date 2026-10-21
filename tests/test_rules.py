from __future__ import annotations

from typing import Any

from bgpmon.config import Config, Target
from bgpmon.models import Event, Route
from bgpmon.rules import (
    BULK_THRESHOLD,
    RuleContext,
    diff_neighbours,
    diff_prefix_set,
    evaluate_routes,
    evaluate_rpki,
    evaluate_visibility,
)
from bgpmon.sources.ris_live import parse_ris_message
from tests.conftest import load_json, make_config


def routes_from(*fixtures: str) -> list[Route]:
    out = []
    for name in fixtures:
        for u in parse_ris_message(load_json("ris_live", name)):
            if not u.withdrawn:
                out.append(Route(u.prefix, u.peer, u.as_path, "ris_live", u.collector))
    return out


def by_type(events: list[Event]) -> dict[str, list[Event]]:
    out: dict[str, list[Event]] = {}
    for ev in events:
        out.setdefault(ev.type, []).append(ev)
    return out


def test_incident_path_raises_forbidden_origin_and_path(orange: Target) -> None:
    res = evaluate_routes(orange, routes_from("hijack_exact_41128.json"), RuleContext(), "ris_live")
    types = by_type(res.events)
    assert set(types) == {"ORIGIN_FORBIDDEN", "PATH_FORBIDDEN_ASN"}
    origin = types["ORIGIN_FORBIDDEN"][0]
    assert origin.severity == "critical" and origin.origin == 41128 and origin.stateful
    assert origin.as_path == [6939, 29802, 22541, 41128]
    assert origin.evidence["relation"] == "exact"
    # L'origine interdite n'est pas comptée deux fois dans PATH_FORBIDDEN_ASN.
    assert sorted(e.evidence["forbidden_asn"] for e in types["PATH_FORBIDDEN_ASN"]) == [
        22541,
        29802,
    ]
    # ORIGIN_UNEXPECTED n'est pas émis en plus d'ORIGIN_FORBIDDEN.
    assert "ORIGIN_UNEXPECTED" not in types


def test_same_condition_from_two_peers_is_aggregated(orange: Target) -> None:
    routes = routes_from("hijack_exact_41128.json", "hijack_exact_41128_peer2.json")
    res = evaluate_routes(orange, routes, RuleContext(), "ris_live")
    forbidden = by_type(res.events)["ORIGIN_FORBIDDEN"]
    assert len(forbidden) == 1
    assert forbidden[0].evidence["peer_count"] == 2
    assert set(forbidden[0].evidence["collectors"]) == {"rrc00", "rrc12"}


def test_unexpected_origin_on_exact_prefix() -> None:
    cfg = make_config()
    target = cfg.targets[0]
    route = Route("90.98.0.0/15", "192.0.2.1", (6939, 64999 + 1), "ripestat")
    types = by_type(evaluate_routes(target, [route], RuleContext(), "ripestat").events)
    assert types["ORIGIN_UNEXPECTED"][0].origin == 65000
    # 65000 est aussi un ASN privé.
    assert types["PATH_SUSPICIOUS"][0].evidence["reason"] == "reserved_asn"


def test_legitimate_more_specifics_are_silent(orange: Target) -> None:
    res = evaluate_routes(orange, routes_from("orange_more_specific.json"), RuleContext(), "x")
    assert res.events == []
    assert res.learned == {(3215, 5511)}


def test_foreign_more_specific_and_private_asn(orange: Target) -> None:
    res = evaluate_routes(orange, routes_from("foreign_more_specific.json"), RuleContext(), "x")
    types = by_type(res.events)
    ms = types["MORE_SPECIFIC_UNEXPECTED"][0]
    assert ms.prefix == "90.98.10.0/24" and ms.origin == 9999
    assert ms.severity == "critical"
    reasons = {e.evidence["asn"] for e in types["PATH_SUSPICIOUS"]}
    assert reasons == {64512, 65001}


def test_more_specific_finer_than_max_length(orange: Target) -> None:
    res = evaluate_routes(orange, routes_from("too_specific.json"), RuleContext(), "x")
    ms = by_type(res.events)["MORE_SPECIFIC_UNEXPECTED"][0]
    assert ms.evidence["reasons"] == ["plus fin que /24"]


def test_loop_detected_but_prepending_is_not_a_loop(orange: Target) -> None:
    res = evaluate_routes(orange, routes_from("loop.json"), RuleContext(), "x")
    assert by_type(res.events)["PATH_SUSPICIOUS"][0].evidence["reason"] == "loop"
    prepend = Route("90.99.0.0/16", "p", (6939, 5511, 3215, 3215, 3215), "x")
    assert evaluate_routes(orange, [prepend], RuleContext(), "x").events == []


def test_as_set_origin(orange: Target) -> None:
    res = evaluate_routes(orange, routes_from("as_set_origin.json"), RuleContext(), "x")
    types = by_type(res.events)
    assert types["PATH_SUSPICIOUS"][0].evidence["reason"] == "as_set_origin"
    assert types["ORIGIN_FORBIDDEN"][0].origin == 41128


def test_unrelated_prefixes_are_ignored(orange: Target) -> None:
    res = evaluate_routes(orange, routes_from("mixed_prefixes.json"), RuleContext(), "x")
    assert res.routes_considered == 1


def test_less_specific_with_forbidden_origin() -> None:
    cfg = make_config(
        [
            {
                "label": "167.32.2.0/24",
                "type": "prefix",
                "resource": "167.32.2.0/24",
                "forbidden_origins": [398290],
                "severity": "high",
            }
        ]
    )
    route = Route("167.32.0.0/16", "p", (6939, 812, 398290, 398290), "ripestat")
    ev = evaluate_routes(cfg.targets[0], [route], RuleContext(), "ripestat").events
    assert [e.type for e in ev] == ["ORIGIN_FORBIDDEN"]
    assert ev[0].evidence["relation"] == "less"


def test_upstream_change_against_learned_history(orange: Target) -> None:
    route = Route("90.99.0.0/16", "p", (6939, 1299, 3215), "x")
    no_baseline = evaluate_routes(orange, [route], RuleContext(), "x")
    assert no_baseline.events == []  # apprentissage, pas d'alerte
    ctx = RuleContext(baseline_done=True, learned_upstreams=lambda origin: {5511})
    ev = evaluate_routes(orange, [route], ctx, "x").events
    assert [e.type for e in ev] == ["PATH_UPSTREAM_CHANGE"]
    assert not ev[0].stateful and ev[0].evidence["upstream"] == 1299
    known = RuleContext(baseline_done=True, learned_upstreams=lambda origin: {1299})
    assert evaluate_routes(orange, [route], known, "x").events == []


def test_upstream_change_against_expected_upstreams() -> None:
    cfg = make_config(
        [
            {
                "label": "90.98.0.0/15",
                "type": "prefix",
                "resource": "90.98.0.0/15",
                "expected_origins": [3215],
                "expected_upstreams": [5511],
            }
        ]
    )
    route = Route("90.98.0.0/15", "p", (6939, 1299, 3215), "x")
    ev = evaluate_routes(cfg.targets[0], [route], RuleContext(), "x").events
    assert ev[0].type == "PATH_UPSTREAM_CHANGE" and ev[0].stateful


def test_new_last_hop_for_unexpected_origin(orange: Target) -> None:
    ctx = RuleContext(baseline_done=True, learned_upstreams=lambda origin: {22541})
    route = Route("90.98.0.0/15", "p", (6939, 199524, 41128), "x")
    types = by_type(evaluate_routes(orange, [route], ctx, "x").events)
    assert types["PATH_SUSPICIOUS"][0].evidence["reason"] == "new_last_hop"


def test_severity_override(orange: Target) -> None:
    ctx = RuleContext(severity_overrides={"PATH_FORBIDDEN_ASN": "info"})
    res = evaluate_routes(orange, routes_from("hijack_exact_41128.json"), ctx, "x")
    assert {e.severity for e in by_type(res.events)["PATH_FORBIDDEN_ASN"]} == {"info"}


def test_visibility_drop_and_baseline(orange: Target) -> None:
    ctx = RuleContext()
    events, base = evaluate_visibility(orange, 160, 165, None, 30, ctx, "ripestat")
    assert events == [] and base == 160
    events, base = evaluate_visibility(orange, 150, 165, 160, 30, ctx, "ripestat")
    assert events == [] and base == 150
    events, base = evaluate_visibility(orange, 50, 165, 150, 30, ctx, "ripestat")
    assert events[0].type == "VISIBILITY_DROP" and base == 150


def test_rpki_rules(orange: Target) -> None:
    ctx = RuleContext()
    results: dict[tuple[str, int], dict[str, Any]] = {
        ("90.98.0.0/15", 41128): {"status": "invalid_asn", "roas": []},
        ("90.98.0.0/18", 54113): {"status": "unknown", "roas": []},
        ("90.99.0.0/16", 3215): {"status": "valid", "roas": [{"origin": "3215"}]},
    }
    events, snap = evaluate_rpki(orange, results, None, ctx)
    assert sorted(e.type for e in events) == ["RPKI_INVALID", "RPKI_UNKNOWN"]
    # Un ROA disparaît : changement d'état signalé.
    results[("90.99.0.0/16", 3215)] = {"status": "unknown", "roas": []}
    events, _ = evaluate_rpki(orange, results, snap, ctx)
    change = [e for e in events if e.type == "RPKI_STATE_CHANGED"]
    assert len(change) == 1 and change[0].evidence["roas_removed"] == [{"origin": "3215"}]


def test_rpki_any_only_reports_changes() -> None:
    t = make_config(
        [{"label": "p", "type": "prefix", "resource": "198.51.100.0/24", "rpki": "any"}]
    ).targets[0]
    results: dict[tuple[str, int], dict[str, Any]] = {
        ("198.51.100.0/24", 64500): {"status": "unknown", "roas": []}
    }
    events, _ = evaluate_rpki(t, results, None, RuleContext())
    assert events == []


def test_asn_prefix_and_neighbour_diffs(config: Config) -> None:
    asn = config.target("AS41128")
    assert asn is not None
    ctx = RuleContext()
    ev = diff_prefix_set(asn, {"10.0.0.0/8"}, {"90.98.0.0/15"}, ctx, "ripestat")
    assert {(e.type, e.prefix) for e in ev} == {
        ("ASN_NEW_PREFIX", "90.98.0.0/15"),
        ("ASN_PREFIX_GONE", "10.0.0.0/8"),
    }
    assert next(e for e in ev if e.type == "ASN_NEW_PREFIX").severity == "high"
    many = {f"10.{i}.0.0/16" for i in range(BULK_THRESHOLD + 5)}
    bulk = diff_prefix_set(asn, set(), many, ctx, "ripestat")
    assert len(bulk) == 1 and bulk[0].evidence["count"] == BULK_THRESHOLD + 5
    nb = diff_neighbours(asn, {6939: "left"}, {22541: "left", 64500: "right"}, ctx, "ripestat")
    assert sorted((e.type, e.severity) for e in nb) == [
        ("ASN_NEIGHBOUR_GONE", "info"),
        ("ASN_NEW_NEIGHBOUR", "high"),
        ("ASN_NEW_NEIGHBOUR", "warning"),
    ]


def test_silence_broken_on_reannouncement() -> None:
    t = make_config(
        [
            {
                "label": "198.193.12.0/24",
                "type": "prefix",
                "resource": "198.193.12.0/24",
                "expect_silent": True,
                "forbidden_origins": [2702],
                "severity": "high",
            }
        ]
    ).targets[0]
    exact = Route("198.193.12.0/24", "p", (6939, 64600), "ris_live")
    more = Route("198.193.12.0/25", "p", (6939, 64601), "ris_live")
    covering = Route("198.192.0.0/14", "p", (6939, 701), "ris_live")
    ev = evaluate_routes(t, [exact, more, covering], RuleContext(), "ris_live").events
    broken = [e for e in ev if e.type == "SILENCE_BROKEN"]
    assert sorted(str(e.prefix) for e in broken) == ["198.193.12.0/24", "198.193.12.0/25"]
    assert all(e.stateful and e.severity == "high" for e in broken)
