from __future__ import annotations

from typing import Any

import pytest
import requests

from bgpmon.config import RipestatSettings
from bgpmon.sources import SourceError
from bgpmon.sources.ripestat import (
    RipeStatClient,
    parse_announced_prefixes,
    parse_asn_neighbours,
    parse_bgp_state,
    parse_routing_status,
    parse_rpki_validation,
)
from tests.conftest import load_json


class FakeResponse:
    def __init__(self, status: int, body: Any = None, headers: dict[str, str] | None = None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self) -> Any:
        if self._body is None:
            raise ValueError("pas de JSON")
        return self._body


class FakeSession:
    def __init__(self, responses: list[Any]):
        self.responses = responses
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.headers: dict[str, str] = {}

    def get(self, url: str, params: dict[str, str], timeout: float) -> Any:
        self.calls.append((url, params))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        pass


def ok(data: dict[str, Any]) -> FakeResponse:
    return FakeResponse(200, {"status": "ok", "messages": [], "data": data})


def client(
    responses: list[Any], **settings: Any
) -> tuple[RipeStatClient, FakeSession, list[float]]:
    session = FakeSession(responses)
    sleeps: list[float] = []
    c = RipeStatClient(
        RipestatSettings(min_interval=0, backoff=1.0, **settings),
        session=session,  # type: ignore[arg-type]
        sleep=sleeps.append,
    )
    return c, session, sleeps


def test_routing_status_keeps_history_separate_from_current_state() -> None:
    rs = parse_routing_status(
        load_json("ripestat", "routing_status_90_98_15.json")["data"], "90.98.0.0/15"
    )
    # last_seen.origin (41128) ne doit PAS être compté comme origine courante.
    assert rs.origins == []
    assert rs.last_seen is not None and rs.last_seen["origin"] == "41128"
    assert rs.more_specifics == [("90.99.0.0/16", 3215), ("90.98.0.0/18", 54113)]
    assert (rs.peers_seeing, rs.total_peers) == (0, 165)


def test_bgp_state_parsing() -> None:
    routes = parse_bgp_state(load_json("ripestat", "bgp_state_167_32_16.json")["data"])
    assert routes[0].prefix == "167.32.0.0/16"
    assert routes[0].collector == "rrc00" and routes[0].peer == "102.208.105.2"
    assert routes[0].as_path[-1] == 398290


def test_other_parsers() -> None:
    assert (
        parse_announced_prefixes(load_json("ripestat", "announced_prefixes_41128.json")["data"])
        == set()
    )
    assert parse_asn_neighbours({"neighbours": [{"asn": 22541, "type": "left"}]}) == {22541: "left"}
    rpki = parse_rpki_validation(load_json("ripestat", "rpki_validation_unknown.json")["data"])
    assert rpki.status == "unknown" and rpki.roas == []


def test_sourceapp_and_retry_with_backoff() -> None:
    c, session, sleeps = client(
        [
            FakeResponse(503),
            requests.ConnectionError("réseau"),
            ok({"x": 1}),
        ]
    )
    assert c.get("routing-status", resource="90.98.0.0/15") == {"x": 1}
    assert len(session.calls) == 3
    assert all(params["sourceapp"] == "bgpmon" for _, params in session.calls)
    assert session.calls[0][0] == "https://stat.ripe.net/data/routing-status/data.json"
    assert sleeps == [1.0, 2.0]


def test_retry_after_is_respected() -> None:
    c, _, sleeps = client([FakeResponse(429, headers={"Retry-After": "7"}), ok({})])
    c.get("bgp-state", resource="1.0.0.0/24")
    assert 7.0 in sleeps


def test_errors_raise_source_error() -> None:
    c, _, _ = client([FakeResponse(503)] * 4)
    with pytest.raises(SourceError, match="injoignable"):
        c.get("routing-status", resource="x")
    c, _, _ = client([FakeResponse(200, {"status": "error", "messages": [["error", "bad"]]})])
    with pytest.raises(SourceError):
        c.get("routing-status", resource="x")
    c, _, _ = client([FakeResponse(404)])
    with pytest.raises(SourceError, match="HTTP 404"):
        c.get("routing-status", resource="x")


def test_short_cache() -> None:
    c, session, _ = client([ok({"n": 1}), ok({"n": 2})], cache_ttl=60)
    assert c.get("asn-neighbours", resource="AS1") == {"n": 1}
    assert c.get("asn-neighbours", resource="AS1") == {"n": 1}
    assert len(session.calls) == 1


def test_rate_limit_waits_between_requests() -> None:
    now = [100.0]
    session = FakeSession([ok({}), ok({})])
    sleeps: list[float] = []
    c = RipeStatClient(
        RipestatSettings(min_interval=0.5, cache_ttl=0),
        session=session,  # type: ignore[arg-type]
        clock=lambda: now[0],
        sleep=sleeps.append,
    )
    c.get("a", resource="1")
    c.get("b", resource="2")
    assert sleeps == [0.5]
