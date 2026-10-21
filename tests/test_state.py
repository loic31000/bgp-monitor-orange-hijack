from __future__ import annotations

from pathlib import Path

from bgpmon.models import ROUTE_EVENT_TYPES, Event, make_key
from bgpmon.state import State, derive_state


def cond(
    event_type: str = "ORIGIN_FORBIDDEN",
    prefix: str = "90.98.0.0/15",
    severity: str = "critical",
    target: str = "T",
) -> Event:
    return Event(
        type=event_type,
        severity=severity,
        target=target,
        source="x",
        key=make_key(event_type, target, prefix),
        message="m",
        stateful=True,
        prefix=prefix,
    )


def test_raise_once_then_resolve(state: State) -> None:
    first = state.reconcile("T", "ripestat", [cond()], ROUTE_EVENT_TYPES)
    assert [e.phase for e in first] == ["raised"]
    # Même condition au cycle suivant : aucune nouvelle transition.
    assert state.reconcile("T", "ripestat", [cond()], ROUTE_EVENT_TYPES) == []
    resolved = state.reconcile("T", "ripestat", [], ROUTE_EVENT_TYPES)
    assert [(e.phase, e.type) for e in resolved] == [("resolved", "ORIGIN_FORBIDDEN")]
    assert resolved[0].message.startswith("Résolu")
    assert state.active_conditions("T") == []
    history = state.query_events(target="T")
    assert [e.phase for e in history] == ["resolved", "raised"]


def test_condition_resolves_only_when_no_source_sees_it(state: State) -> None:
    state.reconcile("T", "ripestat", [cond()], ROUTE_EVENT_TYPES)
    assert state.reconcile("T", "ris_live", [cond()], ROUTE_EVENT_TYPES, "90.98.0.0/15") == []
    assert state.active_conditions("T")[0]["sources"] == ["ripestat", "ris_live"]
    assert state.reconcile("T", "ris_live", [], ROUTE_EVENT_TYPES, "90.98.0.0/15") == []
    assert state.active_conditions("T")[0]["sources"] == ["ripestat"]
    assert len(state.reconcile("T", "ripestat", [], ROUTE_EVENT_TYPES)) == 1


def test_scope_prefix_and_types_limit_resolution(state: State) -> None:
    state.reconcile(
        "T",
        "ris_live",
        [cond(prefix="90.98.0.0/16"), cond(prefix="90.99.0.0/16")],
        ROUTE_EVENT_TYPES,
        None,
    )
    # Une mise à jour sur 90.98.0.0/16 ne touche pas 90.99.0.0/16.
    out = state.reconcile("T", "ris_live", [], ROUTE_EVENT_TYPES, "90.98.0.0/16")
    assert [e.prefix for e in out] == ["90.98.0.0/16"]
    # Un passage RPKI ne résout pas une condition de routage.
    assert state.reconcile("T", "ris_live", [], {"RPKI_INVALID"}) == []
    assert len(state.active_conditions("T")) == 1


def test_reraise_after_resolution(state: State) -> None:
    state.reconcile("T", "s", [cond()], ROUTE_EVENT_TYPES)
    state.reconcile("T", "s", [], ROUTE_EVENT_TYPES)
    again = state.reconcile("T", "s", [cond()], ROUTE_EVENT_TYPES)
    assert [e.phase for e in again] == ["raised"]


def test_visibility_restored_on_resolution(state: State) -> None:
    drop = cond("VISIBILITY_DROP", severity="warning")
    state.reconcile("T", "ripestat", [drop], {"VISIBILITY_DROP"})
    out = state.reconcile("T", "ripestat", [], {"VISIBILITY_DROP"})
    assert out[0].type == "VISIBILITY_RESTORED" and out[0].severity == "info"


def test_persistence_across_restart(tmp_path: Path) -> None:
    db = tmp_path / "s.sqlite3"
    st = State(db)
    st.reconcile("T", "s", [cond()], ROUTE_EVENT_TYPES)
    st.set_snapshot("asn_prefixes", "T", ["1.0.0.0/24"])
    st.learn_upstreams("T", [(3215, 5511)])
    st.rib_apply("rrc00", "192.0.2.1", "90.98.0.0/15", [6939, 41128], "2026-01-01T00:00:00+00:00")
    st.close()
    st = State(db)
    assert st.reconcile("T", "s", [cond()], ROUTE_EVENT_TYPES) == []
    assert st.get_snapshot("asn_prefixes", "T") == ["1.0.0.0/24"]
    assert st.learned_upstreams("T", 3215) == {5511}
    assert st.rib_routes("90.98.0.0/15")[0].as_path == (6939, 41128)
    st.rib_apply("rrc00", "192.0.2.1", "90.98.0.0/15", None, "2026-01-01T00:01:00+00:00")
    assert st.rib_routes("90.98.0.0/15") == []
    st.close()


def test_source_health_counter(state: State) -> None:
    assert state.source_failure("T", "ripestat", "timeout") == 1
    assert state.source_failure("T", "ripestat", "timeout") == 2
    state.source_success("T", "ripestat")
    assert state.source_health("T")[0]["failures"] == 0


def test_query_filters(state: State) -> None:
    state.reconcile("A", "s", [cond(target="A", severity="warning")], ROUTE_EVENT_TYPES)
    state.reconcile("B", "s", [cond("RPKI_INVALID", target="B")], {"RPKI_INVALID"})
    assert [e.target for e in state.query_events(min_severity="high")] == ["B"]
    assert [e.target for e in state.query_events(types=["ORIGIN_FORBIDDEN"])] == ["A"]
    assert state.query_events(since="2999-01-01") == []


def test_derive_state() -> None:
    crit = {"type": "ORIGIN_FORBIDDEN", "severity": "critical", "sources": ["ripestat"]}
    warn = {"type": "RPKI_UNKNOWN", "severity": "warning", "sources": ["rpki"]}
    src = {"type": "SOURCE_ERROR", "severity": "warning", "sources": ["ripestat"]}
    assert derive_state([], [], False, True) == ("OK", "aucune anomalie active")
    assert derive_state([], [], False, False)[0] == "UNKNOWN"  # jamais OK sans données
    assert derive_state([], [], True, True)[0] == "UNKNOWN"  # source en erreur
    assert derive_state([src], [], False, True)[0] == "UNKNOWN"
    assert derive_state([warn], [], False, True)[0] == "WARNING"
    assert derive_state([crit, src], [], True, True)[0] == "ALERT"
    recent = [cond(severity="high")]
    assert derive_state([], recent, False, True)[0] == "ALERT"
    assert derive_state([], [], False, False, expect_silent=True)[0] == "OK"
    # Le silence attendu ne masque pas une source en erreur.
    assert derive_state([], [], True, False, expect_silent=True)[0] == "UNKNOWN"
    info = [cond(severity="info")]
    assert derive_state([], info, False, True)[0] == "OK"
