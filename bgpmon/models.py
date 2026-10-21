"""Types partagés : événements, routes, sévérités et utilitaires BGP."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Un saut d'AS path : un ASN, ou un AS_SET représenté par un tuple trié.
Hop = int | tuple[int, ...]
ASPath = tuple[Hop, ...]

SEVERITIES = ("info", "warning", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
SEVERITY_LABELS = {
    "info": "INFO",
    "warning": "AVERTISSEMENT",
    "high": "ÉLEVÉE",
    "critical": "CRITIQUE",
}

# Types d'événements et libellé français utilisé dans les alertes et le rapport.
EVENT_LABELS = {
    "ORIGIN_UNEXPECTED": "Origine inattendue",
    "ORIGIN_FORBIDDEN": "Origine interdite",
    "MORE_SPECIFIC_UNEXPECTED": "Plus-spécifique inattendu",
    "PATH_FORBIDDEN_ASN": "ASN interdit dans l'AS path",
    "PATH_UPSTREAM_CHANGE": "Changement d'upstream",
    "PATH_SUSPICIOUS": "AS path suspect",
    "VISIBILITY_DROP": "Chute de visibilité",
    "VISIBILITY_RESTORED": "Visibilité rétablie",
    "RPKI_INVALID": "RPKI invalide",
    "RPKI_UNKNOWN": "RPKI inconnu (aucun ROA)",
    "RPKI_STATE_CHANGED": "Changement d'état RPKI",
    "IRR_OBJECT_CREATED": "Objet IRR créé",
    "IRR_OBJECT_MODIFIED": "Objet IRR modifié",
    "IRR_OBJECT_DELETED": "Objet IRR supprimé",
    "ASN_NEW_PREFIX": "Nouveau préfixe annoncé",
    "ASN_PREFIX_GONE": "Préfixe disparu",
    "ASN_NEW_NEIGHBOUR": "Nouveau voisin",
    "ASN_NEIGHBOUR_GONE": "Voisin disparu",
    "SILENCE_BROKEN": "Annonce d'un préfixe censé être silencieux",
    "SOURCE_ERROR": "Source injoignable",
}
EVENT_TYPES = tuple(EVENT_LABELS)

# Types évalués à partir des routes observées (RIPEstat bgp-state ou RIS Live).
ROUTE_EVENT_TYPES = frozenset(
    {
        "ORIGIN_UNEXPECTED",
        "ORIGIN_FORBIDDEN",
        "MORE_SPECIFIC_UNEXPECTED",
        "PATH_FORBIDDEN_ASN",
        "PATH_UPSTREAM_CHANGE",
        "PATH_SUSPICIOUS",
        "SILENCE_BROKEN",
    }
)

# Cible pseudo-globale pour les erreurs de sources non liées à une cible (RIS Live).
GLOBAL_TARGET = "*"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: datetime | None = None) -> str:
    return (ts or utcnow()).astimezone(timezone.utc).isoformat(timespec="seconds")


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


@dataclass
class Event:
    """Événement typé produit par une règle.

    `key` identifie la condition (sans la source) : deux sources qui voient le
    même problème produisent la même clé. `stateful` distingue une condition
    (active tant qu'elle est observée, puis résolue) d'un changement ponctuel.
    """

    type: str
    severity: str
    target: str
    source: str
    key: str
    message: str
    stateful: bool
    timestamp: str = field(default_factory=iso)
    prefix: str | None = None
    origin: int | None = None
    as_path: list[Any] | None = None
    peer: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    phase: str = "raised"  # raised | resolved | oneshot
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def make_key(event_type: str, target: str, *parts: object) -> str:
    return "|".join([event_type, target, *(str(p) for p in parts)])


@dataclass(frozen=True)
class Route:
    """Une route vue par un peer de collecteur pour un préfixe."""

    prefix: str
    peer: str
    as_path: ASPath
    source: str
    collector: str | None = None
    timestamp: str | None = None


# ── Utilitaires AS path ────────────────────────────────────────────────────


def normalize_path(raw: list[Any] | tuple[Any, ...]) -> ASPath:
    """Convertit un AS path brut (JSON) en tuple ; les AS_SET deviennent des tuples triés."""
    hops: list[Hop] = []
    for hop in raw:
        if isinstance(hop, (list, tuple, set, frozenset)):
            members = tuple(sorted({int(a) for a in hop}))
            hops.append(members[0] if len(members) == 1 else members)
        else:
            hops.append(int(hop))
    return tuple(hops)


def strip_prepends(path: ASPath) -> ASPath:
    """Supprime les répétitions consécutives (prepending)."""
    out: list[Hop] = []
    for hop in path:
        if not out or out[-1] != hop:
            out.append(hop)
    return tuple(out)


def path_asns(path: ASPath) -> list[int]:
    asns: list[int] = []
    for hop in path:
        if isinstance(hop, tuple):
            asns.extend(hop)
        else:
            asns.append(hop)
    return asns


def path_to_json(path: ASPath) -> list[Any]:
    return [list(h) if isinstance(h, tuple) else h for h in path]


def origin_of(path: ASPath) -> Hop | None:
    return path[-1] if path else None


def format_path(path: ASPath | list[Any] | None) -> str:
    if not path:
        return "—"
    parts = []
    for hop in path:
        if isinstance(hop, (list, tuple)):
            parts.append("{" + ",".join(str(a) for a in hop) + "}")
        else:
            parts.append(str(hop))
    return " ".join(parts)


# Plages réservées ou privées (RFC 6996, RFC 5398, RFC 6793, RFC 7300, IANA).
_RESERVED_RANGES = (
    (0, 0, "AS0 réservé (RFC 7607)"),
    (23456, 23456, "AS_TRANS (RFC 6793)"),
    (64496, 64511, "ASN de documentation (RFC 5398)"),
    (64512, 65534, "ASN privé (RFC 6996)"),
    (65535, 65535, "ASN réservé (RFC 7300)"),
    (65536, 65551, "ASN de documentation (RFC 5398)"),
    (65552, 131071, "ASN réservé IANA"),
    (4200000000, 4294967294, "ASN privé 32 bits (RFC 6996)"),
    (4294967295, 4294967295, "ASN réservé (RFC 7300)"),
)


def reserved_asn_reason(asn: int) -> str | None:
    for low, high, reason in _RESERVED_RANGES:
        if low <= asn <= high:
            return reason
    return None


def find_loop(path: ASPath) -> int | None:
    """Retourne un ASN qui réapparaît de façon non consécutive (boucle), sinon None."""
    seen: set[int] = set()
    for hop in strip_prepends(path):
        if isinstance(hop, tuple):
            continue
        if hop in seen:
            return hop
        seen.add(hop)
    return None


# ── Utilitaires préfixes ───────────────────────────────────────────────────

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_network(prefix: str) -> Network:
    return ipaddress.ip_network(prefix, strict=False)


def prefix_relation(prefix: str | Network, reference: Network) -> str | None:
    """Relation de `prefix` par rapport à `reference` : exact, more, less ou None."""
    try:
        net = parse_network(prefix) if isinstance(prefix, str) else prefix
    except ValueError:
        return None
    if net.version != reference.version:
        return None
    if net == reference:
        return "exact"
    if net.subnet_of(reference):  # type: ignore[arg-type]
        return "more"
    if net.supernet_of(reference):  # type: ignore[arg-type]
        return "less"
    return None


def parse_asn(value: object) -> int:
    """Accepte 3215, "3215" ou "AS3215" ; lève ValueError sinon."""
    if isinstance(value, bool):
        raise ValueError(f"ASN invalide : {value!r}")
    if isinstance(value, int):
        asn = value
    elif isinstance(value, str):
        text = value.strip().upper()
        if text.startswith("AS"):
            text = text[2:]
        if not text.isdigit():
            raise ValueError(f"ASN invalide : {value!r}")
        asn = int(text)
    else:
        raise ValueError(f"ASN invalide : {value!r}")
    if not 0 <= asn <= 4294967295:
        raise ValueError(f"ASN hors plage : {value!r}")
    return asn
