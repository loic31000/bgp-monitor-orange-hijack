from __future__ import annotations

import hashlib
import json
import lzma
from collections import Counter
from pathlib import Path
from typing import Any

from bgpmon import dossier as dz
from bgpmon.models import parse_network
from bgpmon.sources import SourceError

ROUTING_HISTORY = {
    "time_granularity": 28800,
    "by_origin": [
        {
            "origin": 3215,
            "prefixes": [
                {
                    "prefix": "90.98.0.0/16",
                    "timelines": [
                        {
                            "starttime": "2026-08-30T00:00:00",
                            "endtime": "2026-08-31T23:59:59",
                            "full_peers_seeing": 327,
                        },
                        {
                            "starttime": "2026-09-01T00:00:00",
                            "endtime": "2026-09-02T07:59:59",
                            "full_peers_seeing": 326,
                        },
                    ],
                }
            ],
        },
        {
            "origin": 54113,
            "prefixes": [
                {
                    "prefix": "90.98.0.0/18",
                    "timelines": [
                        {
                            "starttime": "2026-10-05T08:00:00",
                            "endtime": "2026-10-15T23:59:59",
                            "full_peers_seeing": 324,
                        },
                        {
                            "starttime": "2026-10-16T00:00:00",
                            "endtime": "2026-10-21T00:00:00",
                            "full_peers_seeing": 322,
                        },
                    ],
                }
            ],
        },
        {
            "origin": 41128,
            "prefixes": [
                {
                    "prefix": "90.98.0.0/15",
                    "timelines": [
                        {
                            "starttime": "2026-02-24T00:00:00",
                            "endtime": "2026-03-11T23:59:59",
                            "full_peers_seeing": 290,
                        },
                        {
                            "starttime": "2026-04-11T00:00:00",
                            "endtime": "2026-04-22T23:59:59",
                            "full_peers_seeing": 331,
                        },
                    ],
                }
            ],
        },
    ],
}
BGPLAY_APPEAR = {
    "initial_state": [],
    "events": [
        {
            "type": "A",
            "timestamp": "2026-10-05T03:03:15",
            "attrs": {"source_id": "00-1", "path": [6939, 1299, 5511, 54113]},
        },
        {
            "type": "A",
            "timestamp": "2026-10-05T03:10:00",
            "attrs": {"source_id": "00-2", "path": [3356, 5511, 54113, 54113]},
        },
        {
            "type": "A",
            "timestamp": "2026-10-05T18:00:00",
            "attrs": {"source_id": "00-1", "path": [6939, 1299, 54113]},
        },
    ],
}
BGPLAY_WITHDRAW = {
    "initial_state": [
        {"source_id": "00-1", "path": [174, 5511, 3215]},
        {"source_id": "00-2", "path": [6939, 5511, 3215]},
    ],
    "events": [
        {"type": "W", "timestamp": "2026-09-02T05:03:03", "attrs": {"source_id": "00-1"}},
        {"type": "W", "timestamp": "2026-09-02T07:02:40", "attrs": {"source_id": "00-2"}},
    ],
}
ROAS_CSV = (
    "URI,ASN,IP Prefix,Max Length,Not Before,Not After\n"
    "rsync://x,AS3215,90.99.0.0/16,24,2026-01-29 12:48:30,2027-07-01 00:00:00\n"
    "rsync://x,AS3215,90.98.0.0/16,16,2026-04-20 12:45:26,2027-07-01 00:00:00\n"
    "rsync://x,AS13335,1.1.1.0/24,24,2026-01-01 00:00:00,2027-01-01 00:00:00\n"
)
TRANSFERS = {
    "transfers": [
        {
            "transfer_date": "2026-09-03T19:00:00Z",
            "type": "RESOURCE_TRANSFER",
            "ip4nets": {
                "original_set": [{"start_address": "90.98.0.0", "end_address": "90.99.255.255"}],
                "transfer_set": [{"start_address": "90.98.0.0", "end_address": "90.98.255.255"}],
            },
            "source_organization": {"name": "Orange S.A.", "country_code": "FR"},
            "recipient_organization": {"name": "Fastly, Inc.", "country_code": "US"},
        },
        {
            "transfer_date": "2020-01-01T00:00:00Z",
            "type": "RESOURCE_TRANSFER",
            "ip4nets": {
                "transfer_set": [{"start_address": "10.0.0.0", "end_address": "10.0.0.255"}]
            },
            "source_organization": {"name": None},
            "recipient_organization": {"name": "Autre SA"},
        },
    ]
}
RPSL_ROUTE = """route:          90.98.0.0/18
descr:          Fastly
origin:         AS54113
mnt-by:         MAINT-AS54113
notify:         someone@example.net
changed:        ops@example.net 20261005
source:         RADB
last-modified:  2026-10-05T11:49:37Z
"""


def test_redact_masks_emails_but_keeps_domain() -> None:
    out = dz.redact({"a": ["changed: noc@example.net 2026"], "b": 1})
    assert out == {"a": ["changed: <masqué>@example.net 2026"], "b": 1}


def test_parse_rpsl_drops_contact_attributes() -> None:
    obj = dz.parse_rpsl_objects("% commentaire\n\n" + RPSL_ROUTE)[0]
    assert obj["origin"] == ["AS54113"] and "notify" not in obj
    assert obj["changed"] == ["<masqué>@example.net 20261005"]


def test_history_spans_merges_contiguous_bins_and_keeps_gaps() -> None:
    spans = dz.history_spans(ROUTING_HISTORY)
    by = [(s["origin"], s["prefix"], s["start"], s["end"]) for s in spans]
    assert (3215, "90.98.0.0/16", "2026-08-30T00:00:00", "2026-09-02T07:59:59") in by
    assert (54113, "90.98.0.0/18", "2026-10-05T08:00:00", "2026-10-21T00:00:00") in by
    assert len([s for s in spans if s["origin"] == 41128]) == 2  # trou de mars à avril


def test_appearance_and_withdrawal() -> None:
    app = dz.appearance(BGPLAY_APPEAR, 54113)
    assert app["first_announcement"] == "2026-10-05T03:03:15"
    assert app["hourly_upstreams"][0] == {
        "hour": "2026-10-05T03",
        "announcements": 2,
        "upstreams": [(5511, 2)],
    }
    assert app["hourly_upstreams"][1]["upstreams"] == [(1299, 1)]
    wd = dz.withdrawal(BGPLAY_WITHDRAW)
    assert wd["initial_peers"] == 2 and wd["peers_still_announcing_at_window_end"] == 0
    assert wd["last_withdrawal"] == "2026-09-02T07:02:40"


def test_upstream_comparison() -> None:
    target = Counter({1299: 10, 2914: 5, 8434: 1})
    ref = Counter({174: 20, 1299: 8, 2914: 6})
    cmp = dz.compare_upstreams(target, ref)
    assert cmp["share_of_target_routes_via_reference_upstreams_pct"] == 93.8
    assert cmp["reference_upstreams_absent_from_target"] == [{"asn": 174, "reference_routes": 20}]
    assert cmp["target_upstreams_absent_from_reference"] == [{"asn": 8434, "routes": 1}]


def test_filters() -> None:
    scope = parse_network("90.98.0.0/15")
    assert [r["prefix"] for r in dz.filter_roas(ROAS_CSV, scope)] == [
        "90.98.0.0/16",
        "90.99.0.0/16",
    ]
    hits = dz.filter_transfers(TRANSFERS["transfers"], scope=scope)
    assert len(hits) == 1 and hits[0]["recipient_organization"]["name"] == "Fastly, Inc."
    by_name = dz.filter_transfers(TRANSFERS["transfers"], org_name="orange s.a.")
    assert len(by_name) == 1
    text = '{"addresses": ["90.98.0.0/17", "90.98.128.0/18", "151.101.0.0/16"]}'
    assert dz.cidrs_overlapping(text, parse_network("90.98.0.0/18")) == ["90.98.0.0/17"]


def test_reverse_zone_and_ptr_sample_are_bounded() -> None:
    assert dz.reverse_zone(parse_network("90.98.0.0/15")) == "90.in-addr.arpa"
    assert dz.reverse_zone(parse_network("90.98.0.0/18")) == "98.90.in-addr.arpa"
    sample = dz.ptr_sample(parse_network("90.98.0.0/18"), 8)
    assert sample[:2] == ["90.98.0.1", "90.98.8.1"] and len(sample) == 8


class FakeStat:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get_body(self, endpoint: str, **params: Any) -> dict[str, Any]:
        self.calls.append((endpoint, params))
        responses: dict[str, Any] = {
            "routing-status": {
                "origins": [],
                "more_specifics": [{"prefix": "90.98.0.0/18", "origin": 54113}],
                "visibility": {"v4": {"ris_peers_seeing": 0, "total_ris_peers": 165}},
            },
            "routing-history": ROUTING_HISTORY,
            "bgplay": BGPLAY_APPEAR
            if params.get("resource") == "90.98.0.0/18"
            else BGPLAY_WITHDRAW,
            "bgp-state": {
                "timestamp": "2026-10-21T04:00:00",
                "bgp_state": [{"path": [6939, 1299, 54113]}, {"path": [3356, 2914, 54113]}],
            },
            "announced-prefixes": {
                "prefixes": [{"prefix": "151.101.0.0/16"}, {"prefix": "90.98.0.0/18"}]
            },
            "rpki-validation": {"status": "unknown", "validating_roas": []},
            "historical-whois": {
                "versions": [{"version": 1, "from_time": "2026-09-03T07:43:08"}],
                "objects": [{"attributes": []}],
            },
        }
        data = responses.get(endpoint)
        if data is None:
            raise SourceError(f"{endpoint} indisponible")
        return {"status": "ok", "messages": [], "data": data}

    def get(self, endpoint: str, **params: Any) -> dict[str, Any]:
        result: dict[str, Any] = self.get_body(endpoint, **params)["data"]
        return result


def fake_whois(host: str, port: int, query: str, timeout: float) -> str:
    if "inetnum" in query and "-M" not in query:
        return (
            "inetnum: 90.98.0.0 - 90.98.255.255\nnetname: US-FASTLY-20060302\n"
            "org: ORG-FI26-RIPE\nstatus: ALLOCATED PA\ncreated: 2026-09-03T07:43:08Z\n"
        )
    if "-x 90.98.0.0/18" in query and "radb" in host:
        return RPSL_ROUTE
    return "%ERROR:101: no entries found\n"


def fake_http(url: str) -> bytes:
    if url.endswith("roas.csv.xz"):
        return lzma.compress(ROAS_CSV.encode())
    if url.endswith(".sha256"):
        return hashlib.sha256(lzma.compress(ROAS_CSV.encode())).hexdigest().encode()
    if "transfers" in url:
        return json.dumps(TRANSFERS).encode()
    raise OSError("indisponible")


def test_collect_end_to_end_offline(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(dz.Dossier, "doh", lambda self, name, rtype: {"Status": 3})
    stat: Any = FakeStat()
    d = dz.Dossier(tmp_path, stat, whois=fake_whois, http=fake_http, pause=0)
    s = dz.collect(
        "90.98.0.0/18",
        54113,
        tmp_path,
        stat,
        covering="90.98.0.0/15",
        roa_dates=["2026-10-20"],
        reference=1,
        dossier=d,
    )
    r = s["routing"]
    assert r["target_spans"][0]["start"] == "2026-10-05T08:00:00"
    assert r["appearance"]["first_announcement"] == "2026-10-05T03:03:15"
    assert r["upstreams_now"]["distribution"] == [(1299, 1), (2914, 1)]
    assert s["rpki"]["archive_sha256_ok"] is True
    assert s["irr"]["objects"]["RADB"][0]["origin"] == ["AS54113"]
    assert s["registry"]["inetnum"][0]["org"] == ["ORG-FI26-RIPE"]
    assert s["transfers"]["covering"][0]["recipient_organization"]["name"] == "Fastly, Inc."
    files = {p.name for p in (tmp_path / "raw").iterdir()}
    assert {"routing_history_full.json", "roa_archive.json", "ripe_transfers.json"} <= files
    raw = json.loads((tmp_path / "raw" / "irr_RADB_exact.json").read_text("utf-8"))
    assert raw["meta"]["source"].startswith("whois whois.radb.net")
    assert "ops@example.net" not in json.dumps(raw)
    index = json.loads((tmp_path / "INDEX.json").read_text("utf-8"))
    assert all(len(e["sha256_data"]) == 64 for e in index)
    obs = (tmp_path / "OBSERVATIONS.md").read_text("utf-8")
    assert "Première annonce observée (BGPlay) : 2026-10-05T03:03:15" in obs
    assert "Fastly, Inc." in obs


def test_failing_sources_are_recorded_as_unverified(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(dz.Dossier, "doh", lambda self, name, rtype: None)

    def broken_http(url: str) -> bytes:
        raise OSError("réseau coupé")

    def broken_whois(host: str, port: int, query: str, timeout: float) -> str:
        raise OSError("refusé")

    stat: Any = FakeStat()
    d = dz.Dossier(tmp_path, stat, whois=broken_whois, http=broken_http, pause=0)
    s = dz.collect(
        "90.98.0.0/18",
        54113,
        tmp_path,
        stat,
        covering="90.98.0.0/15",
        roa_dates=["2026-10-20"],
        reference=1,
        dossier=d,
    )
    assert any(u.startswith("GET https://ftp.ripe.net/rpki/") for u in s["unverified"])
    assert any(u.startswith("whois whois.radb.net") for u in s["unverified"])
    assert s["rpki"]["archive"] == {}
    assert "## Non vérifié" in (tmp_path / "OBSERVATIONS.md").read_text("utf-8")


def test_apply_redactions_rewrites_raw_and_index(tmp_path: Path) -> None:
    stat: Any = FakeStat()
    d = dz.Dossier(tmp_path, stat, whois=fake_whois, http=fake_http, pause=0)
    d.save("x", "test", "q", {"descr": ["AS-Exemple customers"]})
    (tmp_path / "INDEX.json").write_text(json.dumps(d.index), "utf-8")
    before = d.index[0]["sha256_data"]
    assert dz.apply_redactions(tmp_path, ["as-exemple"]) == 1
    rec = json.loads((tmp_path / "raw" / "x.json").read_text("utf-8"))
    assert rec["data"] == {"descr": ["<masqué> customers"]}
    index = json.loads((tmp_path / "INDEX.json").read_text("utf-8"))
    assert index[0]["sha256_data"] == rec["meta"]["sha256_data"] != before
    assert dz.apply_redactions(tmp_path, ["absent"]) == 0


def test_owner_fields_are_masked_on_save_and_after_the_fact(tmp_path: Path) -> None:
    stat: Any = FakeStat()
    d = dz.Dossier(tmp_path, stat, whois=fake_whois, http=fake_http, pause=0)
    d.save("bp", "test", "q", {"nodes": [{"as_number": 64500, "owner": "Personne Exemple, FR"}]})
    rec = json.loads((tmp_path / "raw" / "bp.json").read_text("utf-8"))
    assert rec["data"]["nodes"] == [{"as_number": 64500, "owner": "<masqué>"}]
    # Fichier produit par une version antérieure : masquage a posteriori, empreinte recalculée.
    rec["data"]["nodes"][0]["owner"] = "Personne Exemple, FR"
    (tmp_path / "raw" / "bp.json").write_text(json.dumps(rec), "utf-8")
    (tmp_path / "INDEX.json").write_text(json.dumps(d.index), "utf-8")
    assert dz.apply_redactions(tmp_path, [], keys=frozenset({"owner"})) == 1
    after = json.loads((tmp_path / "raw" / "bp.json").read_text("utf-8"))
    assert after["data"]["nodes"][0]["owner"] == "<masqué>"
    index = json.loads((tmp_path / "INDEX.json").read_text("utf-8"))
    assert index[0]["sha256_data"] == after["meta"]["sha256_data"]


def test_digest_is_stable_with_integer_keys(tmp_path: Path) -> None:
    stat: Any = FakeStat()
    d = dz.Dossier(tmp_path, stat, whois=fake_whois, http=fake_http, pause=0)
    d.save("h", "test", "q", {"holders": {12479: "A", 9180: "B", 16236: "C"}})
    rec = json.loads((tmp_path / "raw" / "h.json").read_text("utf-8"))
    body = json.dumps(rec["data"], ensure_ascii=False, sort_keys=True, default=str)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() == rec["meta"]["sha256_data"]
