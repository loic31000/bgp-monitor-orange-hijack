"""Canaux d'alerte (console, JSONL, webhook) et répartiteur avec déduplication.

Seules les transitions sont envoyées : apparition (`raised`), résolution
(`resolved`) et changements ponctuels (`oneshot`). Un même couple
(clé de condition, phase) n'est pas renvoyé avant la fin de son cooldown.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Protocol

import requests

from bgpmon.config import AlertChannelConfig, AlertSettings
from bgpmon.models import EVENT_LABELS, SEVERITY_LABELS, SEVERITY_RANK, Event, format_path
from bgpmon.state import State

log = logging.getLogger("bgpmon.alerts")
alert_log = logging.getLogger("bgpmon.alert")

PHASE_LABELS = {"raised": "NOUVEAU", "resolved": "RÉSOLU", "oneshot": "CHANGEMENT"}


def format_text(ev: Event) -> str:
    sev = "RÉSOLU" if ev.phase == "resolved" else SEVERITY_LABELS.get(ev.severity, ev.severity)
    label = EVENT_LABELS.get(ev.type, ev.type)
    parts = [f"[{sev}] {label} — {ev.target} : {ev.message}"]
    details = []
    if ev.as_path:
        details.append(f"AS path {format_path(ev.as_path)}")
    count = ev.evidence.get("peer_count")
    if count:
        details.append(f"{count} peer(s) RIS")
    details.append(f"source {ev.source}")
    parts.append(f"({', '.join(details)})")
    return " ".join(parts)


class Channel(Protocol):
    name: str
    min_severity: str

    def send(self, ev: Event) -> None: ...


class ConsoleChannel:
    name = "console"

    def __init__(self, min_severity: str = "info"):
        self.min_severity = min_severity

    def send(self, ev: Event) -> None:
        high = SEVERITY_RANK[ev.severity] >= SEVERITY_RANK["high"] and ev.phase != "resolved"
        alert_log.log(logging.WARNING if high else logging.INFO, "%s", format_text(ev))


class JsonlChannel:
    name = "jsonl"

    def __init__(self, path: str, min_severity: str = "info"):
        self.path = Path(path)
        self.min_severity = min_severity

    def send(self, ev: Event) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {**ev.to_dict(), "text": format_text(ev)}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            fh.flush()


def detect_format(url: str) -> str:
    lowered = url.lower()
    if "discord.com/api/webhooks" in lowered or "discordapp.com/api/webhooks" in lowered:
        return "discord"
    if "hooks.slack.com" in lowered:
        return "slack"
    if "ntfy" in lowered:
        return "ntfy"
    return "generic"


_NTFY_PRIORITY = {"info": "2", "warning": "3", "high": "4", "critical": "5"}


def build_webhook_request(ev: Event, fmt: str) -> dict[str, Any]:
    """Arguments de `requests.post` selon le format de la cible."""
    text = format_text(ev)
    if fmt == "discord":
        return {"json": {"content": text[:1990], "allowed_mentions": {"parse": []}}}
    if fmt == "slack":
        return {"json": {"text": text}}
    if fmt == "ntfy":
        title = f"bgpmon : {EVENT_LABELS.get(ev.type, ev.type)} ({ev.target})"
        return {
            "data": text.encode("utf-8"),
            "headers": {
                # Les en-têtes HTTP doivent rester en latin-1.
                "Title": title.encode("latin-1", "replace").decode("latin-1"),
                "Priority": "2" if ev.phase == "resolved" else _NTFY_PRIORITY[ev.severity],
                "Tags": "white_check_mark" if ev.phase == "resolved" else "warning",
            },
        }
    return {"json": {"text": text, "event": ev.to_dict()}}


class WebhookChannel:
    name = "webhook"

    def __init__(
        self,
        url: str,
        fmt: str = "auto",
        min_severity: str = "info",
        timeout: float = 10.0,
        session: requests.Session | None = None,
        retries: int = 2,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.url = url
        self.format = detect_format(url) if fmt == "auto" else fmt
        self.min_severity = min_severity
        self.timeout = timeout
        self.session = session or requests.Session()
        self.retries = retries
        self._sleep = sleep

    def send(self, ev: Event) -> None:
        kwargs = build_webhook_request(ev, self.format)
        last = ""
        for attempt in range(self.retries + 1):
            if attempt:
                self._sleep(2.0 * attempt)
            try:
                resp = self.session.post(self.url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                last = type(exc).__name__
                continue
            if resp.status_code < 300:
                return
            last = f"HTTP {resp.status_code}"
            if resp.status_code < 500 and resp.status_code != 429:
                break
        # L'URL n'est jamais journalisée : elle peut contenir un secret.
        raise RuntimeError(f"webhook {self.format} en échec : {last}")


def build_channels(settings: AlertSettings, env: dict[str, str] | None = None) -> list[Channel]:
    env = dict(os.environ) if env is None else env
    channels: list[Channel] = []
    for cfg in settings.channels:
        channel = _build_channel(cfg, env)
        if channel is not None:
            channels.append(channel)
    return channels


def _build_channel(cfg: AlertChannelConfig, env: dict[str, str]) -> Channel | None:
    if cfg.type == "console":
        return ConsoleChannel(cfg.min_severity)
    if cfg.type == "jsonl":
        return JsonlChannel(str(cfg.path), cfg.min_severity)
    url = env.get(cfg.url_env or "", "") or cfg.url or ""
    if not url:
        log.info("Canal webhook désactivé : variable %s non définie", cfg.url_env)
        return None
    if cfg.url and not cfg.url_env:
        log.warning("URL de webhook lue dans la configuration : gardez ce fichier hors de git")
    return WebhookChannel(url, cfg.format, cfg.min_severity, cfg.timeout)


class AlertDispatcher:
    def __init__(
        self,
        channels: list[Channel],
        settings: AlertSettings,
        state: State,
        clock: Callable[[], float] = time.time,
    ):
        self.channels = channels
        self.settings = settings
        self.state = state
        self._clock = clock

    def dispatch(self, events: Iterable[Event]) -> int:
        """Envoie les transitions hors cooldown ; retourne le nombre d'événements envoyés."""
        sent = 0
        for ev in events:
            dedup_key = f"{ev.key}|{ev.phase}"
            now = self._clock()
            last = self.state.alert_last_sent(dedup_key)
            cooldown = self.settings.cooldown_for(ev.type)
            if last is not None and now - last < cooldown:
                log.debug("Alerte %s ignorée (cooldown %ss)", dedup_key, cooldown)
                continue
            delivered = False
            for channel in self.channels:
                if SEVERITY_RANK[ev.severity] < SEVERITY_RANK[channel.min_severity]:
                    continue
                try:
                    channel.send(ev)
                    delivered = True
                except Exception as exc:  # noqa: BLE001 — un canal défaillant ne bloque pas les autres
                    log.error("Canal %s : envoi impossible (%s)", channel.name, exc)
            if delivered:
                self.state.mark_alert_sent(dedup_key, now)
                sent += 1
        return sent
