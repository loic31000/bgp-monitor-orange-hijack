"""Client WebSocket RIS Live : abonnements, heartbeat, reconnexion avec backoff."""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Protocol

import websocket

from bgpmon.config import Config, RisLiveSettings
from bgpmon.models import ASPath, normalize_path

log = logging.getLogger("bgpmon.ris_live")


@dataclass(frozen=True)
class RouteUpdate:
    """Une annonce ou un retrait d'un préfixe par un peer RIS."""

    prefix: str
    peer: str
    peer_asn: int | None
    collector: str | None
    as_path: ASPath
    withdrawn: bool
    timestamp: float


def build_subscriptions(config: Config) -> list[dict[str, Any]]:
    """Un abonnement par préfixe surveillé (plus et moins spécifiques), et un
    abonnement par ASN dont on veut voir toute nouvelle annonce en origine."""
    subs: list[dict[str, Any]] = []
    for t in config.prefix_targets:
        subs.append(
            {
                "type": "ris_subscribe",
                "data": {
                    "prefix": t.resource,
                    "moreSpecific": True,
                    "lessSpecific": True,
                    "type": "UPDATE",
                    "socketOptions": {"includeRaw": False},
                },
            }
        )
    for t in config.asn_targets:
        if t.ris_live_origin:
            subs.append(
                {
                    "type": "ris_subscribe",
                    "data": {
                        "path": f"{t.asn}$",
                        "type": "UPDATE",
                        "socketOptions": {"includeRaw": False},
                    },
                }
            )
    return subs


def parse_ris_message(msg: dict[str, Any]) -> list[RouteUpdate]:
    """Décode un message `ris_message` de type UPDATE en annonces et retraits."""
    if msg.get("type") != "ris_message":
        return []
    data = msg.get("data") or {}
    if data.get("type") != "UPDATE":
        return []
    peer = str(data.get("peer", ""))
    try:
        peer_asn: int | None = int(data["peer_asn"])
    except (KeyError, TypeError, ValueError):
        peer_asn = None
    host = data.get("host")
    collector = str(host).split(".")[0] if host else None
    ts = float(data.get("timestamp") or time.time())
    try:
        path = normalize_path(data.get("path") or [])
    except (TypeError, ValueError):
        log.debug("AS path illisible ignoré : %r", data.get("path"))
        return []
    updates: list[RouteUpdate] = []
    for ann in data.get("announcements") or []:
        for prefix in ann.get("prefixes") or []:
            updates.append(RouteUpdate(str(prefix), peer, peer_asn, collector, path, False, ts))
    for prefix in data.get("withdrawals") or []:
        updates.append(RouteUpdate(str(prefix), peer, peer_asn, collector, (), True, ts))
    return updates


class _Socket(Protocol):
    def send(self, payload: str) -> Any: ...
    def recv(self) -> Any: ...
    def settimeout(self, timeout: float) -> None: ...
    def close(self) -> None: ...


def backoff_delay(attempt: int, maximum: float, rng: Callable[[], float] = random.random) -> float:
    """Backoff exponentiel plafonné avec gigue (1 s, 2 s, 4 s… jusqu'à `maximum`)."""
    base = min(maximum, float(2 ** min(attempt, 16)))
    return min(maximum, base * (0.5 + rng() / 2) + 0.5)


class RisLiveClient:
    def __init__(
        self,
        settings: RisLiveSettings,
        subscriptions: list[dict[str, Any]],
        on_update: Callable[[RouteUpdate], None],
        on_status: Callable[[str, str | None], None],
        connect: Callable[..., _Socket] = websocket.create_connection,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.settings = settings
        self.subscriptions = subscriptions
        self.on_update = on_update
        self.on_status = on_status
        self._connect = connect
        self._clock = clock
        self._ws: _Socket | None = None
        self.messages_received = 0

    def run(self, stop: threading.Event) -> None:
        attempt = 0
        while not stop.is_set():
            started = self._clock()
            try:
                self._session(stop)
            except Exception as exc:  # noqa: BLE001 — toute erreur réseau mène à une reconnexion
                self.on_status("disconnected", f"{type(exc).__name__}: {exc}")
                log.warning("RIS Live déconnecté : %s", exc)
            finally:
                self._close()
            if stop.is_set():
                break
            # Une session longue remet le compteur de backoff à zéro.
            attempt = 0 if self._clock() - started > 120 else attempt + 1
            delay = backoff_delay(attempt, self.settings.reconnect_max_seconds)
            log.info("RIS Live : reconnexion dans %.0f s (tentative %d)", delay, attempt + 1)
            stop.wait(delay)
        self.on_status("stopped", None)

    def _close(self) -> None:
        if self._ws is not None:
            with suppress(Exception):
                self._ws.close()
            self._ws = None

    def _session(self, stop: threading.Event) -> None:
        log.info("Connexion à RIS Live (%s)", self.settings.url)
        ws = self._connect(self.settings.url, timeout=15)
        self._ws = ws
        for sub in self.subscriptions:
            ws.send(json.dumps(sub))
        log.info("RIS Live connecté, %d abonnement(s)", len(self.subscriptions))
        self.on_status("connected", None)
        ws.settimeout(1.0)
        heartbeat = self.settings.heartbeat_seconds
        last_rx = last_ping = self._clock()
        while not stop.is_set():
            now = self._clock()
            if now - last_ping >= heartbeat:
                ws.send(json.dumps({"type": "ping"}))
                last_ping = now
            if now - last_rx > 3 * heartbeat:
                raise TimeoutError(f"aucun message depuis {now - last_rx:.0f} s")
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                continue
            if raw is None or raw == "":
                raise ConnectionError("connexion fermée par le serveur")
            last_rx = self._clock()
            self._handle(raw)

    def _handle(self, raw: Any) -> None:
        try:
            msg = json.loads(raw)
        except (TypeError, ValueError):
            log.debug("Message RIS Live non JSON ignoré")
            return
        mtype = msg.get("type")
        if mtype == "pong":
            return
        if mtype == "ris_error":
            log.error("RIS Live a signalé une erreur : %s", msg.get("data"))
            self.on_status("error", str(msg.get("data")))
            return
        updates = parse_ris_message(msg)
        if updates:
            self.messages_received += 1
        for upd in updates:
            self.on_update(upd)
