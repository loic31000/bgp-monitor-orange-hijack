"""Moteur de règles : transforme des observations en événements typés.

Toutes les fonctions sont pures (aucun accès réseau ni base) : l'historique
appris est fourni par un `RuleContext`, ce qui les rend testables avec des
messages simulés.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from bgpmon.config import Target
from bgpmon.models import (
    Event,
    Route,
    find_loop,
    format_path,
    iso,
    make_key,
    parse_network,
    path_asns,
    path_to_json,
    prefix_relation,
    reserved_asn_reason,
    strip_prepends,
)

# Sévérités par défaut des types qui ne reprennent pas la sévérité de la cible.
DEFAULT_SEVERITY = {
    "PATH_UPSTREAM_CHANGE": "warning",
    "PATH_SUSPICIOUS": "warning",
    "VISIBILITY_DROP": "warning",
    "VISIBILITY_RESTORED": "info",
    "RPKI_UNKNOWN": "warning",
    "RPKI_STATE_CHANGED": "warning",
    "IRR_OBJECT_MODIFIED": "warning",
    "IRR_OBJECT_DELETED": "warning",
    "ASN_PREFIX_GONE": "info",
    "ASN_NEW_NEIGHBOUR": "warning",
    "ASN_NEIGHBOUR_GONE": "info",
    "SOURCE_ERROR": "warning",
}

RELATION_LABELS = {"exact": "préfixe exact", "more": "plus-spécifique", "less": "moins-spécifique"}
BULK_THRESHOLD = 10
MAX_EVIDENCE_PEERS = 25
MAX_SAMPLE_PATHS = 5


@dataclass
class RuleContext:
    baseline_done: bool = False
    learned_upstreams: Callable[[int], set[int]] = field(default=lambda origin: set())
    severity_overrides: dict[str, str] = field(default_factory=dict)
    now: str = field(default_factory=iso)

    def severity(self, event_type: str, default: str) -> str:
        return self.severity_overrides.get(event_type, default)


def _asns(asns: Iterable[int]) -> str:
    return ", ".join(f"AS{a}" for a in asns) or "—"


class _Aggregator:
    """Regroupe les routes qui déclenchent la même condition (même clé)."""

    def __init__(self, target: Target, ctx: RuleContext, source: str):
        self.target = target
        self.ctx = ctx
        self.source = source
        self.events: dict[str, Event] = {}

    def add(
        self,
        event_type: str,
        route: Route,
        key_parts: tuple[object, ...],
        message: str,
        *,
        severity: str | None = None,
        stateful: bool = True,
        origin: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        key = make_key(event_type, self.target.label, *key_parts)
        ev = self.events.get(key)
        if ev is None:
            sev = severity or DEFAULT_SEVERITY.get(event_type, self.target.severity)
            ev = Event(
                type=event_type,
                severity=self.ctx.severity(event_type, sev),
                target=self.target.label,
                source=self.source,
                key=key,
                message=message,
                stateful=stateful,
                phase="raised" if stateful else "oneshot",
                timestamp=self.ctx.now,
                prefix=route.prefix,
                origin=origin,
                as_path=path_to_json(route.as_path),
                peer=route.peer,
                evidence={
                    "relation": prefix_relation(route.prefix, self.target.network),
                    "peers": [],
                    "peer_count": 0,
                    "collectors": [],
                    "sample_paths": [],
                    "prefixes": [],
                    **(extra or {}),
                },
            )
            self.events[key] = ev
        evd = ev.evidence
        if route.peer not in evd["peers"]:
            evd["peer_count"] += 1
            if len(evd["peers"]) < MAX_EVIDENCE_PEERS:
                evd["peers"].append(route.peer)
        if route.collector and route.collector not in evd["collectors"]:
            evd["collectors"].append(route.collector)
        sample = format_path(route.as_path)
        if sample not in evd["sample_paths"] and len(evd["sample_paths"]) < MAX_SAMPLE_PATHS:
            evd["sample_paths"].append(sample)
        if route.prefix not in evd["prefixes"]:
            evd["prefixes"].append(route.prefix)


@dataclass
class RouteEvaluation:
    events: list[Event]
    learned: set[tuple[int, int]]  # couples (origine, upstream) observés
    routes_considered: int


def evaluate_routes(
    target: Target, routes: Iterable[Route], ctx: RuleContext, source: str
) -> RouteEvaluation:
    """Applique les règles d'origine, de plus-spécifique et d'AS path."""
    net = target.network
    agg = _Aggregator(target, ctx, source)
    learned: set[tuple[int, int]] = set()
    considered = 0
    expected = set(target.expected_origins)
    forbidden = set(target.forbidden_origins)
    allowed_ms = set(target.more_specific_allowed)

    for route in routes:
        rel = prefix_relation(route.prefix, net)
        path = strip_prepends(route.as_path)
        if rel is None or not path:
            continue
        considered += 1
        last = path[-1]
        origin = last if isinstance(last, int) else None
        origins = [last] if isinstance(last, int) else list(last)
        rel_label = RELATION_LABELS[rel]

        if target.expect_silent and rel != "less":
            who = f"AS{origin}" if origin is not None else format_path((last,))
            agg.add(
                "SILENCE_BROKEN",
                route,
                (route.prefix, origin),
                f"{route.prefix} ({rel_label} de {target.resource}, silence attendu) "
                f"de nouveau annoncé par {who}",
                origin=origin,
            )

        if origin is None:
            agg.add(
                "PATH_SUSPICIOUS",
                route,
                (route.prefix, "as_set_origin"),
                f"{route.prefix} : origine en AS_SET {format_path((last,))}",
                extra={"reason": "as_set_origin"},
            )

        for o in origins:
            if o in forbidden:
                agg.add(
                    "ORIGIN_FORBIDDEN",
                    route,
                    (route.prefix, o),
                    f"{route.prefix} ({rel_label} de {target.resource}) annoncé par "
                    f"l'origine interdite AS{o}",
                    origin=o,
                )

        if (
            rel == "exact"
            and expected
            and origin is not None
            and origin not in expected
            and origin not in forbidden
        ):
            agg.add(
                "ORIGIN_UNEXPECTED",
                route,
                (route.prefix, origin),
                f"{route.prefix} annoncé par AS{origin} ; origine attendue : {_asns(expected)}",
                origin=origin,
            )

        if rel == "more":
            reasons = []
            if allowed_ms and origin not in allowed_ms and origin not in forbidden:
                who = f"AS{origin}" if origin is not None else "un AS_SET"
                reasons.append(f"origine {who} non autorisée")
            plen = parse_network(route.prefix).prefixlen
            if target.max_prefix_length is not None and plen > target.max_prefix_length:
                reasons.append(f"plus fin que /{target.max_prefix_length}")
            if reasons:
                agg.add(
                    "MORE_SPECIFIC_UNEXPECTED",
                    route,
                    (route.prefix, origin),
                    f"Plus-spécifique {route.prefix} de {target.resource} : {', '.join(reasons)}",
                    origin=origin,
                    extra={"reasons": reasons},
                )

        asns = path_asns(path)
        for asn in sorted(set(asns) & set(target.forbidden_path_asns)):
            # L'origine interdite est déjà couverte par ORIGIN_FORBIDDEN.
            if asn == origin and asn in forbidden and asns.count(asn) == 1:
                continue
            agg.add(
                "PATH_FORBIDDEN_ASN",
                route,
                (route.prefix, asn),
                f"AS{asn} (interdit) dans l'AS path de {route.prefix} : {format_path(path)}",
                origin=origin,
                extra={"forbidden_asn": asn},
            )

        loop = find_loop(path)
        if loop is not None:
            agg.add(
                "PATH_SUSPICIOUS",
                route,
                (route.prefix, "loop", loop),
                f"Boucle dans l'AS path de {route.prefix} (AS{loop} répété) : {format_path(path)}",
                origin=origin,
                extra={"reason": "loop", "asn": loop},
            )
        for asn in sorted(set(asns)):
            why = reserved_asn_reason(asn)
            if why:
                agg.add(
                    "PATH_SUSPICIOUS",
                    route,
                    (route.prefix, "reserved", asn),
                    f"{why} : AS{asn} dans l'AS path de {route.prefix}",
                    origin=origin,
                    extra={"reason": "reserved_asn", "asn": asn},
                )

        if origin is None or len(path) < 2 or not isinstance(path[-2], int):
            continue
        upstream = path[-2]
        learned.add((origin, upstream))
        if rel == "less":
            continue
        # Historique appris : vide tant que la référence n'est pas établie.
        known = ctx.learned_upstreams(origin) if ctx.baseline_done else set()
        if origin in expected:
            if target.expected_upstreams:
                if upstream not in target.expected_upstreams:
                    agg.add(
                        "PATH_UPSTREAM_CHANGE",
                        route,
                        (route.prefix, origin, upstream),
                        f"{route.prefix} : upstream AS{upstream} → AS{origin}, attendu "
                        f"{_asns(target.expected_upstreams)}",
                        origin=origin,
                        extra={"upstream": upstream, "mode": "expected"},
                    )
            elif known and upstream not in known:
                agg.add(
                    "PATH_UPSTREAM_CHANGE",
                    route,
                    (origin, upstream),
                    f"Nouvel upstream AS{upstream} → AS{origin} ({route.prefix}), "
                    f"jamais observé (connus : {_asns(sorted(known))})",
                    stateful=False,
                    origin=origin,
                    extra={"upstream": upstream, "mode": "learned", "known": sorted(known)},
                )
        elif known and upstream not in known:
            # Origine déjà vue avec d'autres upstreams ; une origine inédite relève
            # des règles d'origine.
            agg.add(
                "PATH_SUSPICIOUS",
                route,
                (origin, "new_last_hop", upstream),
                f"Dernier saut jamais vu pour AS{origin} : AS{upstream} → AS{origin} "
                f"({route.prefix})",
                stateful=False,
                origin=origin,
                extra={"reason": "new_last_hop", "upstream": upstream, "known": sorted(known)},
            )

    return RouteEvaluation(list(agg.events.values()), learned, considered)


def evaluate_visibility(
    target: Target,
    seeing: int,
    total: int,
    baseline: int | None,
    threshold_pct: float,
    ctx: RuleContext,
    source: str,
) -> tuple[list[Event], int]:
    """VISIBILITY_DROP tant que la visibilité reste sous la référence moins le seuil.

    La référence suit la visibilité tant qu'il n'y a pas de chute ; elle est
    figée pendant une chute pour que la résolution soit nette.
    """
    if not baseline:
        return [], seeing
    floor = baseline * (1 - threshold_pct / 100)
    if seeing >= floor:
        return [], seeing
    drop = round(100 * (baseline - seeing) / baseline, 1)
    ev = Event(
        type="VISIBILITY_DROP",
        severity=ctx.severity("VISIBILITY_DROP", DEFAULT_SEVERITY["VISIBILITY_DROP"]),
        target=target.label,
        source=source,
        key=make_key("VISIBILITY_DROP", target.label, target.resource),
        message=(
            f"Visibilité de {target.resource} : {seeing}/{total} peers RIS "
            f"(référence {baseline}, -{drop} %)"
        ),
        stateful=True,
        timestamp=ctx.now,
        prefix=target.resource,
        evidence={"seeing": seeing, "total": total, "baseline": baseline, "drop_pct": drop},
    )
    return [ev], baseline


def evaluate_rpki(
    target: Target,
    results: dict[tuple[str, int], dict[str, Any]],
    previous: dict[str, dict[str, Any]] | None,
    ctx: RuleContext,
    source: str = "rpki",
) -> tuple[list[Event], dict[str, dict[str, Any]]]:
    """`results` : (préfixe, origine) → {"status": ..., "roas": [...]}."""
    events: list[Event] = []
    snapshot = dict(previous or {})
    for (prefix, origin), res in sorted(results.items()):
        status = str(res.get("status", "unknown"))
        roas = res.get("roas") or []
        pair = f"{prefix}|{origin}"
        common: dict[str, Any] = {
            "target": target.label,
            "source": source,
            "timestamp": ctx.now,
            "prefix": prefix,
            "origin": origin,
        }
        if target.rpki == "expect_valid":
            if status.startswith("invalid"):
                events.append(
                    Event(
                        type="RPKI_INVALID",
                        severity=ctx.severity("RPKI_INVALID", target.severity),
                        key=make_key("RPKI_INVALID", target.label, prefix, origin),
                        message=f"RPKI {status} pour {prefix} annoncé par AS{origin}",
                        stateful=True,
                        evidence={"status": status, "roas": roas},
                        **common,
                    )
                )
            elif status in ("unknown", "not-found", "not_found"):
                events.append(
                    Event(
                        type="RPKI_UNKNOWN",
                        severity=ctx.severity("RPKI_UNKNOWN", DEFAULT_SEVERITY["RPKI_UNKNOWN"]),
                        key=make_key("RPKI_UNKNOWN", target.label, prefix, origin),
                        message=f"Aucun ROA ne couvre {prefix} (AS{origin}) : statut RPKI inconnu",
                        stateful=True,
                        evidence={"status": status, "roas": roas},
                        **common,
                    )
                )
        before = (previous or {}).get(pair)
        if before is not None:
            old_roas = before.get("roas") or []
            added = [r for r in roas if r not in old_roas]
            removed = [r for r in old_roas if r not in roas]
            if before.get("status") != status or added or removed:
                parts = []
                if before.get("status") != status:
                    parts.append(f"statut {before.get('status')} → {status}")
                if added:
                    parts.append(f"{len(added)} ROA apparu(s)")
                if removed:
                    parts.append(f"{len(removed)} ROA disparu(s)")
                digest = hashlib.sha256(repr((status, roas)).encode()).hexdigest()[:12]
                events.append(
                    Event(
                        type="RPKI_STATE_CHANGED",
                        severity=ctx.severity(
                            "RPKI_STATE_CHANGED", DEFAULT_SEVERITY["RPKI_STATE_CHANGED"]
                        ),
                        key=make_key("RPKI_STATE_CHANGED", target.label, prefix, origin, digest),
                        message=f"RPKI {prefix} / AS{origin} : {', '.join(parts)}",
                        stateful=False,
                        phase="oneshot",
                        evidence={
                            "old_status": before.get("status"),
                            "new_status": status,
                            "roas_added": added,
                            "roas_removed": removed,
                        },
                        **common,
                    )
                )
        snapshot[pair] = {"status": status, "roas": roas}
    return events, snapshot


def _set_diff_events(
    target: Target,
    ctx: RuleContext,
    source: str,
    event_type: str,
    items: list[str],
    severity: str,
    single: Callable[[str], str],
    bulk: Callable[[int], str],
    extra: Callable[[str], dict[str, Any]] | None = None,
) -> list[Event]:
    """Un événement par élément, ou un seul événement groupé au-delà du seuil."""
    if not items:
        return []
    sev = ctx.severity(event_type, severity)
    if len(items) > BULK_THRESHOLD:
        digest = hashlib.sha256("\n".join(items).encode()).hexdigest()[:12]
        return [
            Event(
                type=event_type,
                severity=sev,
                target=target.label,
                source=source,
                key=make_key(event_type, target.label, "bulk", digest),
                message=bulk(len(items)),
                stateful=False,
                phase="oneshot",
                timestamp=ctx.now,
                origin=target.asn,
                evidence={"items": items, "count": len(items)},
            )
        ]
    return [
        Event(
            type=event_type,
            severity=sev,
            target=target.label,
            source=source,
            key=make_key(event_type, target.label, item),
            message=single(item),
            stateful=False,
            phase="oneshot",
            timestamp=ctx.now,
            origin=target.asn,
            prefix=item if "/" in item else None,
            evidence=extra(item) if extra else {},
        )
        for item in items
    ]


def diff_prefix_set(
    target: Target, old: set[str], new: set[str], ctx: RuleContext, source: str
) -> list[Event]:
    added, gone = sorted(new - old), sorted(old - new)
    asn = target.asn
    return _set_diff_events(
        target,
        ctx,
        source,
        "ASN_NEW_PREFIX",
        added,
        target.severity,
        lambda p: f"AS{asn} annonce un nouveau préfixe : {p}",
        lambda n: f"AS{asn} annonce {n} nouveaux préfixes",
    ) + _set_diff_events(
        target,
        ctx,
        source,
        "ASN_PREFIX_GONE",
        gone,
        DEFAULT_SEVERITY["ASN_PREFIX_GONE"],
        lambda p: f"AS{asn} n'annonce plus {p}",
        lambda n: f"AS{asn} n'annonce plus {n} préfixes",
    )


def diff_neighbours(
    target: Target, old: dict[int, str], new: dict[int, str], ctx: RuleContext, source: str
) -> list[Event]:
    asn = target.asn
    added = [str(a) for a in sorted(set(new) - set(old))]
    gone = [str(a) for a in sorted(set(old) - set(new))]
    events: list[Event] = []
    # Un nouvel upstream (type "left") hérite de la sévérité de la cible.
    upstream_added = [a for a in added if new[int(a)] == "left"]
    other_added = [a for a in added if new[int(a)] != "left"]
    events += _set_diff_events(
        target,
        ctx,
        source,
        "ASN_NEW_NEIGHBOUR",
        upstream_added,
        target.severity,
        lambda a: f"AS{asn} a un nouveau voisin amont : AS{a}",
        lambda n: f"AS{asn} a {n} nouveaux voisins amont",
        lambda a: {"neighbour": int(a), "neighbour_type": "left"},
    )
    events += _set_diff_events(
        target,
        ctx,
        source,
        "ASN_NEW_NEIGHBOUR",
        other_added,
        DEFAULT_SEVERITY["ASN_NEW_NEIGHBOUR"],
        lambda a: f"AS{asn} a un nouveau voisin : AS{a} ({new[int(a)]})",
        lambda n: f"AS{asn} a {n} nouveaux voisins",
        lambda a: {"neighbour": int(a), "neighbour_type": new[int(a)]},
    )
    events += _set_diff_events(
        target,
        ctx,
        source,
        "ASN_NEIGHBOUR_GONE",
        gone,
        DEFAULT_SEVERITY["ASN_NEIGHBOUR_GONE"],
        lambda a: f"AS{asn} n'a plus AS{a} comme voisin ({old[int(a)]})",
        lambda n: f"AS{asn} a perdu {n} voisins",
        lambda a: {"neighbour": int(a), "neighbour_type": old[int(a)]},
    )
    return events


def irr_events(
    target: Target,
    server: str,
    changes: list[tuple[str, dict[str, Any], dict[str, Any] | None]],
    changed_attrs: Callable[[dict[str, Any], dict[str, Any]], list[str]],
    ctx: RuleContext,
    source: str = "irr",
) -> list[Event]:
    events: list[Event] = []
    labels = {"created": "créé", "modified": "modifié", "deleted": "supprimé"}
    for kind, obj, before in changes:
        etype = f"IRR_OBJECT_{kind.upper()}"
        attrs = obj.get("attributes", {})
        origin_txt = (attrs.get("origin") or [""])[0]
        origin = (
            int(origin_txt[2:])
            if origin_txt.upper().startswith("AS") and origin_txt[2:].isdigit()
            else None
        )
        prefix = (attrs.get("route") or attrs.get("route6") or [None])[0]
        if kind == "created":
            suspicious = not target.is_prefix or origin not in target.expected_origins
            severity = target.severity if suspicious else "info"
        else:
            severity = DEFAULT_SEVERITY[etype]
        evidence: dict[str, Any] = {
            "server": server,
            "class": obj.get("class"),
            "object_key": obj.get("key"),
            "attributes": attrs,
        }
        detail = ""
        if kind == "modified" and before is not None:
            changed = changed_attrs(before, obj)
            evidence["changed_attributes"] = changed
            evidence["previous_attributes"] = before.get("attributes", {})
            detail = f" (attributs : {', '.join(changed) or '—'})"
        mnt = ", ".join(attrs.get("mnt-by", [])) or "—"
        events.append(
            Event(
                type=etype,
                severity=ctx.severity(etype, severity),
                target=target.label,
                source=source,
                key=make_key(
                    etype,
                    target.label,
                    server,
                    obj.get("class"),
                    obj.get("key"),
                    obj.get("fingerprint"),
                ),
                message=(
                    f"Objet {obj.get('class')} {prefix or obj.get('key')}"
                    f"{f' (origine {origin_txt})' if origin_txt else ''} {labels[kind]} dans "
                    f"{server}, mnt-by {mnt}{detail}"
                ),
                stateful=False,
                phase="oneshot",
                timestamp=ctx.now,
                prefix=prefix,
                origin=origin,
                evidence=evidence,
            )
        )
    return events


def source_error_event(
    target_label: str, source: str, failures: int, error: str, ctx: RuleContext
) -> Event:
    return Event(
        type="SOURCE_ERROR",
        severity=ctx.severity("SOURCE_ERROR", DEFAULT_SEVERITY["SOURCE_ERROR"]),
        target=target_label,
        source=source,
        key=make_key("SOURCE_ERROR", target_label, source),
        message=f"Source {source} en erreur depuis {failures} cycle(s) : {error}",
        stateful=True,
        timestamp=ctx.now,
        evidence={"failures": failures, "error": error},
    )
