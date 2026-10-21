from __future__ import annotations

from bgpmon.config import Config, IrrServer, IrrSettings, Target
from bgpmon.rules import RuleContext, irr_events
from bgpmon.sources.irr import (
    IrrClient,
    changed_attributes,
    diff_objects,
    parse_rpsl,
    queries_for_target,
)
from tests.conftest import load_text


def snapshot(text: str) -> dict[str, dict]:  # type: ignore[type-arg]
    return {o.object_id: o.to_dict() for o in parse_rpsl(text, "ALTDB")}


def test_parse_rpsl_keeps_only_non_personal_attributes() -> None:
    objs = parse_rpsl(load_text("irr", "altdb_90_98_15_v1.txt"), "ALTDB")
    assert [o.key for o in objs] == ["90.98.0.0/15AS41128", "90.99.0.0/16AS3215"]
    first = objs[0]
    assert first.attributes["origin"] == ["AS41128"]
    assert "changed" not in first.attributes and "descr" not in first.attributes
    assert "admin-c" not in first.attributes
    assert "changed" in first.attr_hashes  # empreinte seulement
    assert "noc@example.net" not in str(first.to_dict())


def test_parse_aut_num_skips_comments() -> None:
    objs = parse_rpsl(load_text("irr", "ripe_aut_num.txt"), "RIPE")
    assert len(objs) == 1 and objs[0].object_class == "aut-num" and objs[0].key == "AS41128"
    assert objs[0].attributes["as-name"] == ["ORANGEFR-GRX-AS"]
    assert "import" not in objs[0].attributes


def test_diff_detects_create_modify_delete_and_ignores_volatile() -> None:
    old = snapshot(load_text("irr", "altdb_90_98_15_v1.txt"))
    new = snapshot(load_text("irr", "altdb_90_98_15_v2.txt"))
    kinds = {(k, o["key"]) for k, o, _ in diff_objects(old, new)}
    assert kinds == {
        ("modified", "90.98.0.0/15AS41128"),
        ("created", "90.98.0.0/15AS270118"),
        ("deleted", "90.99.0.0/16AS3215"),
    }
    _, after, before = next(c for c in diff_objects(old, new) if c[0] == "modified")
    assert before is not None
    assert changed_attributes(before, after) == ["changed", "descr"]
    # Seul rpki-ov-state change : pas de modification.
    volatile = load_text("irr", "altdb_90_98_15_v1.txt").replace("not_found", "valid")
    assert diff_objects(old, snapshot(volatile)) == []


def test_irr_events(orange: Target) -> None:
    old = snapshot(load_text("irr", "altdb_90_98_15_v1.txt"))
    new = snapshot(load_text("irr", "altdb_90_98_15_v2.txt"))
    events = irr_events(orange, "ALTDB", diff_objects(old, new), changed_attributes, RuleContext())
    by = {e.type: e for e in events}
    assert by["IRR_OBJECT_CREATED"].severity == "critical"  # origine non attendue
    assert by["IRR_OBJECT_CREATED"].origin == 270118
    assert by["IRR_OBJECT_MODIFIED"].evidence["changed_attributes"] == ["changed", "descr"]
    assert by["IRR_OBJECT_DELETED"].prefix == "90.99.0.0/16"
    assert all(not e.stateful for e in events)


def test_queries(orange: Target, config: Config) -> None:
    asn = config.target("AS41128")
    assert asn is not None
    assert queries_for_target(orange) == ["-T route -x 90.98.0.0/15", "-T route -M 90.98.0.0/15"]
    assert queries_for_target(asn) == [
        "-T aut-num AS41128",
        "-i origin AS41128",
    ]


def test_client_isolates_failing_server(orange: Target) -> None:
    calls: list[tuple[str, str]] = []

    def fake_query(host: str, port: int, query: str, timeout: float) -> str:
        calls.append((host, query))
        if host == "down.example":
            raise OSError("connexion refusée")
        return load_text("irr", "altdb_90_98_15_v1.txt")

    settings = IrrSettings(
        query_delay=0,
        servers=(
            IrrServer("RADB", "whois.radb.net", query_prefix="-s RADB"),
            IrrServer("DOWN", "down.example"),
        ),
    )
    result = IrrClient(settings, query_fn=fake_query).fetch(orange)
    assert set(result.objects) == {"RADB"} and "DOWN" in result.errors
    assert calls[0] == ("whois.radb.net", "-s RADB -T route -x 90.98.0.0/15")
