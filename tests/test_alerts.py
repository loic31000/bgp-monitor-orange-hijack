from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bgpmon.alerts import (
    AlertDispatcher,
    JsonlChannel,
    WebhookChannel,
    build_channels,
    build_webhook_request,
    detect_format,
    format_text,
)
from bgpmon.config import AlertChannelConfig, AlertSettings
from bgpmon.models import Event
from bgpmon.state import State


def event(phase: str = "raised", severity: str = "critical", key: str = "K") -> Event:
    return Event(
        type="ORIGIN_FORBIDDEN",
        severity=severity,
        target="90.98.0.0/15",
        source="ris_live",
        key=key,
        message="90.98.0.0/15 annoncé par l'origine interdite AS41128",
        stateful=True,
        phase=phase,
        prefix="90.98.0.0/15",
        origin=41128,
        as_path=[6939, 29802, 22541, 41128],
        evidence={"peer_count": 3},
    )


class Recorder:
    name = "recorder"

    def __init__(self, min_severity: str = "info"):
        self.min_severity = min_severity
        self.events: list[Event] = []

    def send(self, ev: Event) -> None:
        self.events.append(ev)


class Failing(Recorder):
    name = "failing"

    def send(self, ev: Event) -> None:
        raise RuntimeError("boom")


def test_format_text_is_french() -> None:
    text = format_text(event())
    assert text.startswith("[CRITIQUE] Origine interdite — 90.98.0.0/15")
    assert "6939 29802 22541 41128" in text and "3 peer(s) RIS" in text
    assert format_text(event("resolved")).startswith("[RÉSOLU]")


def test_dedup_and_cooldown(state: State) -> None:
    now = [1000.0]
    rec = Recorder()
    d = AlertDispatcher(
        [rec], AlertSettings(cooldown_seconds={"default": 600}), state, clock=lambda: now[0]
    )
    assert d.dispatch([event(), event()]) == 1  # doublon dans le même lot
    now[0] += 300
    assert d.dispatch([event()]) == 0  # encore en cooldown
    assert d.dispatch([event("resolved")]) == 1  # la résolution est une autre transition
    now[0] += 400
    assert d.dispatch([event()]) == 1
    assert [e.phase for e in rec.events] == ["raised", "resolved", "raised"]


def test_per_type_cooldown(state: State) -> None:
    settings = AlertSettings(cooldown_seconds={"default": 3600, "ORIGIN_FORBIDDEN": 0})
    rec = Recorder()
    d = AlertDispatcher([rec], settings, state, clock=lambda: 5.0)
    d.dispatch([event()])
    d.dispatch([event()])
    assert len(rec.events) == 2


def test_min_severity_and_failing_channel(state: State) -> None:
    high_only, everything = Recorder("high"), Recorder()
    d = AlertDispatcher([Failing(), high_only, everything], AlertSettings(), state)
    d.dispatch([event(severity="warning", key="W"), event(key="C")])
    assert [e.key for e in high_only.events] == ["C"]
    assert [e.key for e in everything.events] == ["W", "C"]


def test_jsonl_channel(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    JsonlChannel(str(path)).send(event())
    record = json.loads(path.read_text("utf-8").strip())
    assert record["type"] == "ORIGIN_FORBIDDEN" and record["text"].startswith("[CRITIQUE]")


def test_detect_format() -> None:
    assert detect_format("https://discord.com/api/webhooks/1/abc") == "discord"
    assert detect_format("https://hooks.slack.com/services/T/B/x") == "slack"
    assert detect_format("https://ntfy.sh/mon-sujet") == "ntfy"
    assert detect_format("https://example.org/hook") == "generic"


def test_webhook_payloads() -> None:
    assert "content" in build_webhook_request(event(), "discord")["json"]
    assert "text" in build_webhook_request(event(), "slack")["json"]
    ntfy = build_webhook_request(event(), "ntfy")
    assert ntfy["headers"]["Priority"] == "5" and isinstance(ntfy["data"], bytes)
    ntfy["headers"]["Title"].encode("latin-1")  # en-tête HTTP valide
    generic = build_webhook_request(event(), "generic")["json"]
    assert generic["event"]["origin"] == 41128


class FakePost:
    def __init__(self, statuses: list[int]):
        self.statuses = statuses
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, timeout: float, **kwargs: Any) -> Any:
        self.calls.append({"url": url, **kwargs})
        status = self.statuses.pop(0)
        return type("R", (), {"status_code": status})()


def test_webhook_retries_then_succeeds() -> None:
    session = FakePost([502, 204])
    ch = WebhookChannel(
        "https://hooks.slack.com/services/x",
        session=session,  # type: ignore[arg-type]
        sleep=lambda s: None,
    )
    ch.send(event())
    assert len(session.calls) == 2 and session.calls[0]["json"]["text"].startswith("[CRITIQUE]")


def test_webhook_url_comes_from_environment() -> None:
    settings = AlertSettings(
        channels=(
            AlertChannelConfig(type="webhook", url_env="BGPMON_WEBHOOK_URL"),
            AlertChannelConfig(type="console"),
        )
    )
    assert [c.name for c in build_channels(settings, env={})] == ["console"]
    channels = build_channels(settings, env={"BGPMON_WEBHOOK_URL": "https://ntfy.sh/t"})
    webhook = channels[0]
    assert isinstance(webhook, WebhookChannel) and webhook.format == "ntfy"
