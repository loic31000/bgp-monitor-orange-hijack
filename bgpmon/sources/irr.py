"""Lecture passive des objets IRR (route, route6, aut-num) par whois, et diff.

Seuls quelques attributs non personnels sont conservés en clair. Les autres
(descr, changed, notify…) peuvent contenir des noms ou des adresses e-mail :
ils ne sont stockés que sous forme d'empreinte, ce qui suffit à détecter une
modification sans conserver la donnée.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from bgpmon.config import IrrServer, IrrSettings, Target
from bgpmon.sources import SourceError

log = logging.getLogger("bgpmon.irr")

KEPT_ATTRIBUTES = (
    "route",
    "route6",
    "origin",
    "aut-num",
    "as-name",
    "mnt-by",
    "member-of",
    "org",
    "status",
    "source",
    "created",
    "last-modified",
)
# Attributs ajoutés dynamiquement par certains serveurs : exclus de l'empreinte.
VOLATILE_ATTRIBUTES = frozenset({"rpki-ov-state"})
WATCHED_CLASSES = frozenset({"route", "route6", "aut-num"})


@dataclass(frozen=True)
class IrrObject:
    server: str
    object_class: str
    key: str
    attributes: dict[str, list[str]]  # attributs conservés uniquement
    fingerprint: str
    attr_hashes: dict[str, str] = field(default_factory=dict)

    @property
    def object_id(self) -> str:
        return f"{self.server}|{self.object_class}|{self.key}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "class": self.object_class,
            "key": self.key,
            "attributes": self.attributes,
            "fingerprint": self.fingerprint,
            "attr_hashes": self.attr_hashes,
        }


def whois_query(host: str, port: int, query: str, timeout: float) -> str:
    """Requête whois brute (RFC 3912) en lecture seule."""
    chunks: list[bytes] = []
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(query.encode("ascii") + b"\r\n")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def parse_rpsl(text: str, server: str) -> list[IrrObject]:
    objects: list[IrrObject] = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        attrs: list[tuple[str, str]] = []
        for line in block.split("\n"):
            if not line or line.startswith(("%", "#")):
                continue
            if line[0] in " \t+" and attrs:
                name, value = attrs[-1]
                attrs[-1] = (name, f"{value} {line.lstrip('+').strip()}".strip())
                continue
            name, sep, value = line.partition(":")
            if not sep:
                continue
            attrs.append((name.strip().lower(), value.strip()))
        if not attrs or attrs[0][0] not in WATCHED_CLASSES:
            continue
        obj_class, primary = attrs[0]
        grouped: dict[str, list[str]] = {}
        for name, value in attrs:
            grouped.setdefault(name, []).append(value)
        if obj_class in ("route", "route6"):
            origin = (grouped.get("origin") or ["?"])[0].upper()
            key = f"{primary}{origin}"
        else:
            key = primary.upper()
        stable = [(n, v) for n, v in attrs if n not in VOLATILE_ATTRIBUTES]
        objects.append(
            IrrObject(
                server=server,
                object_class=obj_class,
                key=key,
                attributes={k: v for k, v in grouped.items() if k in KEPT_ATTRIBUTES},
                fingerprint=_digest("\n".join(f"{n}:{v}" for n, v in stable)),
                attr_hashes={
                    k: _digest("\n".join(v))
                    for k, v in grouped.items()
                    if k not in VOLATILE_ATTRIBUTES
                },
            )
        )
    return objects


def queries_for_target(target: Target) -> list[str]:
    if target.is_prefix:
        cls = "route6" if target.network.version == 6 else "route"
        return [f"-T {cls} -x {target.resource}", f"-T {cls} -M {target.resource}"]
    return [f"-T aut-num AS{target.asn}", f"-i origin AS{target.asn}"]


@dataclass
class IrrFetch:
    """Résultat d'un passage IRR pour une cible : objets par serveur et erreurs."""

    objects: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


class IrrClient:
    def __init__(
        self,
        settings: IrrSettings,
        query_fn: Callable[[str, int, str, float], str] = whois_query,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.settings = settings
        self._query = query_fn
        self._sleep = sleep

    def _query_server(self, server: IrrServer, target: Target) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        for q in queries_for_target(target):
            full = f"{server.query_prefix} {q}".strip()
            try:
                text = self._query(server.host, server.port, full, self.settings.timeout)
            except OSError as exc:
                raise SourceError(f"whois {server.host} : {exc}") from exc
            if "%ERROR:" in text and "no entries found" not in text.lower():
                raise SourceError(f"whois {server.host} : {text.strip().splitlines()[-1]}")
            for obj in parse_rpsl(text, server.name):
                found[obj.object_id] = obj.to_dict()
            if self.settings.query_delay:
                self._sleep(self.settings.query_delay)
        return found

    def fetch(self, target: Target) -> IrrFetch:
        result = IrrFetch()
        for server in self.settings.servers:
            try:
                result.objects[server.name] = self._query_server(server, target)
            except SourceError as exc:
                log.warning("IRR %s pour %s : %s", server.name, target.label, exc)
                result.errors[server.name] = str(exc)
        return result


def diff_objects(
    old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]
) -> list[tuple[str, dict[str, Any], dict[str, Any] | None]]:
    """Retourne (created|modified|deleted, objet courant, ancien objet)."""
    changes: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = []
    for oid, obj in sorted(new.items()):
        before = old.get(oid)
        if before is None:
            changes.append(("created", obj, None))
        elif before.get("fingerprint") != obj.get("fingerprint"):
            changes.append(("modified", obj, before))
    for oid, obj in sorted(old.items()):
        if oid not in new:
            changes.append(("deleted", obj, None))
    return changes


def changed_attributes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    a, b = before.get("attr_hashes", {}), after.get("attr_hashes", {})
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
