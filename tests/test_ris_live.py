from __future__ import annotations

import json
import threading
from itertools import pairwise
from typing import Any

import pytest
import websocket

from bgpmon.config import RisLiveSettings
from bgpmon.sources import ris_live
from bgpmon.sources.ris_live import (
    RisLiveClient,
    RouteUpdate,
    backoff_delay,
    build_subscriptions,
    parse_ris_message,
)
from tests.conftest import ASN_TARGET, ORANGE_TARGET, load_json, make_config


def test_parse_announcement_and_withdrawal() -> None:
    ann = parse_ris_message(load_json("ris_live", "hijack_exact_41128.json"))
    assert ann == [
        RouteUpdate(
            "90.98.0.0/15",
            "192.0.2.10",
            6939,
            "rrc00",
            (6939, 29802, 22541, 41128),
            False,
            1791390000.0,
        )
    ]
    wd = parse_ris_message(load_json("ris_live", "withdraw_exact.json"))
    assert len(wd) == 1 and wd[0].withdrawn and wd[0].as_path == ()


def test_parse_as_set_and_multiple_prefixes() -> None:
    upd = parse_ris_message(load_json("ris_live", "as_set_origin.json"))
    assert upd[0].as_path == (6939, 5511, (3215, 41128))
    mixed = parse_ris_message(load_json("ris_live", "mixed_prefixes.json"))
    assert [u.prefix for u in mixed] == ["87.242.65.0/24", "90.98.0.0/16", "90.156.129.0/24"]


def test_non_update_messages_are_ignored() -> None:
    assert parse_ris_message(load_json("ris_live", "pong.json")) == []
    assert parse_ris_message({"type": "ris_message", "data": {"type": "KEEPALIVE"}}) == []


def test_subscriptions() -> None:
    cfg = make_config([ORANGE_TARGET, ASN_TARGET])
    subs = build_subscriptions(cfg)
    assert subs[0]["type"] == "ris_subscribe"
    assert subs[0]["data"]["prefix"] == "90.98.0.0/15"
    assert subs[0]["data"]["moreSpecific"] is True and subs[0]["data"]["lessSpecific"] is True
    assert subs[1]["data"]["path"] == "41128$"


def test_backoff_is_exponential_and_capped() -> None:
    delays = [backoff_delay(i, 300, rng=lambda: 1.0) for i in range(12)]
    assert delays[:4] == [1.5, 2.5, 4.5, 8.5]
    assert max(delays) == 300
    assert all(a <= b for a, b in pairwise(delays))


class FakeSocket:
    def __init__(self, messages: list[Any]):
        self.sent: list[dict[str, Any]] = []
        self.messages = messages
        self.closed = False

    def send(self, payload: str) -> None:
        self.sent.append(json.loads(payload))

    def settimeout(self, timeout: float) -> None:
        pass

    def recv(self) -> Any:
        if not self.messages:
            raise ConnectionError("fin du flux simulé")
        item = self.messages.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self) -> None:
        self.closed = True


def test_client_subscribes_dispatches_and_reconnects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ris_live, "backoff_delay", lambda attempt, maximum: 0.0)
    stop = threading.Event()
    sockets = [
        FakeSocket(
            [
                json.dumps(load_json("ris_live", "hijack_exact_41128.json")),
                json.dumps(load_json("ris_live", "pong.json")),
                "pas du json",
            ]
        ),
        FakeSocket([json.dumps(load_json("ris_live", "withdraw_exact.json"))]),
    ]
    connects: list[str] = []

    def connect(url: str, timeout: float) -> FakeSocket:
        connects.append(url)
        if len(connects) == len(sockets):
            # Après la deuxième connexion, on demande l'arrêt à la fin du flux.
            threading.Timer(0.2, stop.set).start()
        return sockets[min(len(connects), len(sockets)) - 1]

    updates: list[RouteUpdate] = []
    statuses: list[str] = []
    cfg = make_config([ORANGE_TARGET])
    client = RisLiveClient(
        RisLiveSettings(),
        build_subscriptions(cfg),
        updates.append,
        lambda s, d: statuses.append(s),
        connect=connect,
    )
    client.run(stop)
    assert [u.withdrawn for u in updates][:2] == [False, True]
    assert sockets[0].sent[0]["type"] == "ris_subscribe"
    assert all(s.closed for s in sockets)
    assert statuses[:3] == ["connected", "disconnected", "connected"]
    assert statuses[-1] == "stopped"


def test_heartbeat_ping_and_silence_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ris_live, "backoff_delay", lambda attempt, maximum: 0.0)
    now = [0.0]

    def clock() -> float:
        now[0] += 2.0
        return now[0]

    stop = threading.Event()
    sock = FakeSocket([websocket.WebSocketTimeoutException()] * 50)
    statuses: list[tuple[str, str | None]] = []

    def on_status(status: str, detail: str | None) -> None:
        statuses.append((status, detail))
        if status == "disconnected":
            stop.set()

    client = RisLiveClient(
        RisLiveSettings(heartbeat_seconds=5),
        [],
        lambda u: None,
        on_status,
        connect=lambda url, timeout: sock,
        clock=clock,
    )
    client.run(stop)
    assert {"type": "ping"} in sock.sent
    assert statuses[1][0] == "disconnected" and "aucun message" in (statuses[1][1] or "")


def test_ris_error_is_reported() -> None:
    statuses: list[str] = []
    client = RisLiveClient(RisLiveSettings(), [], lambda u: None, lambda s, d: statuses.append(s))
    client._handle(json.dumps(load_json("ris_live", "ris_error.json")))
    assert statuses == ["error"]
