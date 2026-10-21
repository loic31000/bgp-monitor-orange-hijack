"""Client HTTP RIPEstat (lecture seule) et décodage des réponses utiles."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import requests

from bgpmon import __version__
from bgpmon.config import RipestatSettings
from bgpmon.models import Route, normalize_path, parse_network, utcnow
from bgpmon.sources import SourceError

log = logging.getLogger("bgpmon.ripestat")

_RETRY_STATUS = {429, 500, 502, 503, 504}
CacheKey = tuple[str, tuple[tuple[str, str], ...]]


class RipeStatClient:
    """Session réutilisée, timeout, retries avec backoff, débit limité et cache court."""

    def __init__(
        self,
        settings: RipestatSettings,
        session: requests.Session | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.settings = settings
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", f"bgpmon/{__version__} (+passive monitor)")
        self._clock = clock
        self._sleep = sleep
        self._last_request = 0.0
        self._cache: dict[CacheKey, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def close(self) -> None:
        self.session.close()

    def _throttle(self) -> None:
        wait = self.settings.min_interval - (self._clock() - self._last_request)
        if wait > 0:
            self._sleep(wait)
        self._last_request = self._clock()

    def get(self, endpoint: str, **params: Any) -> dict[str, Any]:
        """Appelle `/data/<endpoint>/data.json` et retourne le champ `data`."""
        query = {k: str(v) for k, v in params.items() if v is not None}
        query["sourceapp"] = self.settings.sourceapp
        cache_key = (endpoint, tuple(sorted(query.items())))
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and cached[0] > self._clock():
                return cached[1]
            data = self._fetch(endpoint, query)
            if self.settings.cache_ttl:
                self._cache[cache_key] = (self._clock() + self.settings.cache_ttl, data)
                if len(self._cache) > 2048:
                    now = self._clock()
                    self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
            return data

    def _fetch(self, endpoint: str, query: dict[str, str]) -> dict[str, Any]:
        url = f"{self.settings.base_url}/{endpoint}/data.json"
        last_error = "erreur inconnue"
        for attempt in range(self.settings.retries + 1):
            if attempt:
                delay = self.settings.backoff * (2 ** (attempt - 1))
                log.debug("RIPEstat %s : nouvelle tentative dans %.1fs", endpoint, delay)
                self._sleep(delay)
            self._throttle()
            try:
                resp = self.session.get(url, params=query, timeout=self.settings.timeout)
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                continue
            if resp.status_code in _RETRY_STATUS:
                last_error = f"HTTP {resp.status_code}"
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    self._sleep(min(float(retry_after), 120.0))
                continue
            if resp.status_code != 200:
                raise SourceError(f"RIPEstat {endpoint} : HTTP {resp.status_code}")
            try:
                body = resp.json()
            except ValueError as exc:
                raise SourceError(f"RIPEstat {endpoint} : réponse non JSON") from exc
            if body.get("status") != "ok" or not isinstance(body.get("data"), dict):
                raise SourceError(
                    f"RIPEstat {endpoint} : statut {body.get('status')!r} {body.get('messages')!r}"
                )
            for level, text in body.get("messages") or []:
                if level == "error":
                    raise SourceError(f"RIPEstat {endpoint} : {text}")
            data: dict[str, Any] = body["data"]
            return data
        raise SourceError(f"RIPEstat {endpoint} injoignable : {last_error}")

    # ── Endpoints ──
    def routing_status(self, prefix: str) -> RoutingStatus:
        return parse_routing_status(self.get("routing-status", resource=prefix), prefix)

    def bgp_state(self, prefix: str) -> list[Route]:
        return parse_bgp_state(self.get("bgp-state", resource=prefix))

    def announced_prefixes(self, asn: int, window_hours: int) -> set[str]:
        start = (utcnow() - timedelta(hours=window_hours)).strftime("%Y-%m-%dT%H:%M")
        return parse_announced_prefixes(
            self.get("announced-prefixes", resource=f"AS{asn}", starttime=start)
        )

    def asn_neighbours(self, asn: int) -> dict[int, str]:
        return parse_asn_neighbours(self.get("asn-neighbours", resource=f"AS{asn}"))

    def rpki_validation(self, asn: int, prefix: str) -> RpkiResult:
        return parse_rpki_validation(self.get("rpki-validation", resource=asn, prefix=prefix))

    def prefix_routing_consistency(self, prefix: str) -> list[dict[str, Any]]:
        data = self.get("prefix-routing-consistency", resource=prefix)
        return [r for r in data.get("routes", []) if isinstance(r, dict)]


# ── Décodage ──────────────────────────────────────────────────────────────


@dataclass
class RoutingStatus:
    prefix: str
    origins: list[int] = field(default_factory=list)
    more_specifics: list[tuple[str, int]] = field(default_factory=list)
    less_specifics: list[tuple[str, int]] = field(default_factory=list)
    peers_seeing: int = 0
    total_peers: int = 0
    first_seen: dict[str, Any] | None = None
    last_seen: dict[str, Any] | None = None
    query_time: str | None = None


def _origin_pairs(items: Any) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for item in items or []:
        try:
            out.append((str(item["prefix"]), int(item["origin"])))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def parse_routing_status(data: dict[str, Any], prefix: str) -> RoutingStatus:
    """`last_seen` est conservé à part : il décrit l'historique, pas l'état courant."""
    family = "v6" if parse_network(prefix).version == 6 else "v4"
    vis: dict[str, Any] = data.get("visibility") or {}
    # Format courant : {"v4": {...}, "v6": {...}} ; ancien format : champs à plat.
    fam: dict[str, Any] = vis[family] if isinstance(vis.get(family), dict) else vis
    origins = []
    for o in data.get("origins") or []:
        try:
            origins.append(int(o["origin"]))
        except (KeyError, TypeError, ValueError):
            continue
    return RoutingStatus(
        prefix=prefix,
        origins=origins,
        more_specifics=_origin_pairs(data.get("more_specifics")),
        less_specifics=_origin_pairs(data.get("less_specifics")),
        peers_seeing=int(fam.get("ris_peers_seeing", 0) or 0),
        total_peers=int(fam.get("total_ris_peers", 0) or 0),
        first_seen=data.get("first_seen"),
        last_seen=data.get("last_seen"),
        query_time=data.get("query_time"),
    )


def parse_bgp_state(data: dict[str, Any]) -> list[Route]:
    """`source_id` vaut "<rrc>-<ip du peer>", par ex. "00-102.208.105.2"."""
    routes: list[Route] = []
    ts = data.get("timestamp")
    for entry in data.get("bgp_state") or []:
        try:
            source_id = str(entry["source_id"])
            path = normalize_path(entry["path"])
            prefix = str(entry["target_prefix"])
        except (KeyError, TypeError, ValueError):
            continue
        rrc, _, peer = source_id.partition("-")
        routes.append(
            Route(
                prefix=prefix,
                peer=peer or source_id,
                as_path=path,
                source="ripestat",
                collector=f"rrc{rrc}" if rrc.isdigit() else None,
                timestamp=ts,
            )
        )
    return routes


def parse_announced_prefixes(data: dict[str, Any]) -> set[str]:
    return {str(p["prefix"]) for p in data.get("prefixes") or [] if "prefix" in p}


def parse_asn_neighbours(data: dict[str, Any]) -> dict[int, str]:
    out: dict[int, str] = {}
    for n in data.get("neighbours") or []:
        try:
            out[int(n["asn"])] = str(n.get("type", "uncertain"))
        except (KeyError, TypeError, ValueError):
            continue
    return out


@dataclass
class RpkiResult:
    status: str  # valid | invalid | invalid_asn | invalid_length | unknown
    roas: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "roas": self.roas}


def parse_rpki_validation(data: dict[str, Any]) -> RpkiResult:
    roas = []
    for roa in data.get("validating_roas") or []:
        roas.append(
            {
                "origin": roa.get("origin"),
                "prefix": roa.get("prefix"),
                "max_length": roa.get("max_length"),
                "validity": roa.get("validity"),
            }
        )
    roas.sort(key=lambda r: (str(r["prefix"]), str(r["origin"]), str(r["max_length"])))
    return RpkiResult(status=str(data.get("status", "unknown")).lower(), roas=roas)
