from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from bgpmon.config import Config, Target, parse_config
from bgpmon.state import State

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Aucun test ne doit atteindre le réseau."""

    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("accès réseau interdit pendant les tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def load_json(*parts: str) -> Any:
    return json.loads(FIXTURES.joinpath(*parts).read_text(encoding="utf-8"))


def load_text(*parts: str) -> str:
    return FIXTURES.joinpath(*parts).read_text(encoding="utf-8")


ORANGE_TARGET: dict[str, Any] = {
    "label": "90.98.0.0/15",
    "type": "prefix",
    "resource": "90.98.0.0/15",
    "role": "Espace Orange France",
    "expected_origins": [3215],
    "forbidden_origins": [41128],
    "forbidden_path_asns": [41128, 22541, 29802],
    "max_prefix_length": 24,
    "allow_more_specific_from": [3215],
    "rpki": "expect_valid",
    "irr": "watch",
    "severity": "critical",
}
ASN_TARGET: dict[str, Any] = {
    "label": "AS41128",
    "type": "asn",
    "resource": 41128,
    "watch_prefix_set": True,
    "watch_neighbours": True,
    "ris_live_origin": True,
    "irr": "watch",
    "severity": "high",
}


def make_config(
    targets: list[dict[str, Any]] | None = None,
    settings: dict[str, Any] | None = None,
) -> Config:
    base_settings: dict[str, Any] = {
        "db_path": ":memory:",
        "log_file": None,
        "irr": {"servers": [{"name": "ALTDB", "host": "whois.altdb.net"}], "query_delay": 0},
        "alerts": {"channels": []},
    }
    base_settings.update(settings or {})
    return parse_config(
        {"version": 3, "settings": base_settings, "targets": targets or [ORANGE_TARGET]}
    )


@pytest.fixture
def config() -> Config:
    return make_config([ORANGE_TARGET, ASN_TARGET])


@pytest.fixture
def orange(config: Config) -> Target:
    target = config.target("90.98.0.0/15")
    assert target is not None
    return target


@pytest.fixture
def state() -> Iterator[State]:
    st = State(":memory:")
    yield st
    st.close()
