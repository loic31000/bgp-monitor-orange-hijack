"""Orchestration : collecte (réseau) → règles → état → alertes.

La collecte (`collect_*`) n'accède qu'au réseau et peut tourner dans un thread
dédié. Le traitement (`process_*`, `handle_live_*`) accède à SQLite et doit
rester dans un seul thread.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from bgpmon.alerts import AlertDispatcher
from bgpmon.config import Config, Target
from bgpmon.models import (
    GLOBAL_TARGET,
    ROUTE_EVENT_TYPES,
    Event,
    Route,
    iso,
    path_to_json,
    prefix_relation,
    strip_prepends,
)
from bgpmon.rules import (
    RuleContext,
    diff_neighbours,
    diff_prefix_set,
    evaluate_routes,
    evaluate_rpki,
    evaluate_visibility,
    irr_events,
    source_error_event,
)
from bgpmon.sources import SourceError
from bgpmon.sources.irr import IrrClient, IrrFetch, changed_attributes, diff_objects
from bgpmon.sources.ripestat import RipeStatClient, RoutingStatus
from bgpmon.sources.ris_live import RouteUpdate
from bgpmon.state import CORE_SOURCES, State, derive_state

log = logging.getLogger("bgpmon.monitor")


@dataclass
class PrefixObservation:
    target: Target
    error: str | None = None
    status: RoutingStatus | None = None
    routes: list[Route] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)
    rpki: dict[tuple[str, int], dict[str, Any]] | None = None
    rpki_error: str | None = None
    consistency: list[dict[str, Any]] | None = None


@dataclass
class AsnObservation:
    target: Target
    error: str | None = None
    prefixes: set[str] | None = None
    neighbours: dict[int, str] | None = None
    neighbours_error: str | None = None


@dataclass
class IrrObservation:
    target: Target
    fetch: IrrFetch


Observation = PrefixObservation | AsnObservation | IrrObservation


class Monitor:
    def __init__(
        self,
        config: Config,
        state: State,
        ripestat: RipeStatClient,
        irr: IrrClient | None,
        dispatcher: AlertDispatcher,
    ):
        self.config = config
        self.settings = config.settings
        self.state = state
        self.ripestat = ripestat
        self.irr = irr
        self.dispatcher = dispatcher
        self._networks = {t.label: t.network for t in config.prefix_targets}

    # ── Collecte (réseau uniquement) ──────────────────────────────────────
    def collect(self, target: Target) -> PrefixObservation | AsnObservation:
        return self.collect_prefix(target) if target.is_prefix else self.collect_asn(target)

    def collect_prefix(self, target: Target) -> PrefixObservation:
        obs = PrefixObservation(target)
        rs = self.settings.ripestat
        try:
            obs.status = self.ripestat.routing_status(target.resource)
            routes = self.ripestat.bgp_state(target.resource)
            related = [p for p, _ in obs.status.more_specifics + obs.status.less_specifics]
            related = list(dict.fromkeys(p for p in related if p != target.resource))
            queried, skipped = (
                related[: rs.max_more_specific_queries],
                related[rs.max_more_specific_queries :],
            )
            for prefix in queried:
                routes.extend(self.ripestat.bgp_state(prefix))
            # Au-delà du plafond, seule l'origine (routing-status) est connue.
            for prefix, origin in obs.status.more_specifics + obs.status.less_specifics:
                if prefix in skipped:
                    routes.append(Route(prefix, "routing-status", (origin,), "ripestat"))
            obs.routes = routes
            obs.truncated = skipped
            if skipped:
                log.warning(
                    "%s : %d préfixes liés non détaillés (plafond %d)",
                    target.label,
                    len(skipped),
                    rs.max_more_specific_queries,
                )
        except SourceError as exc:
            obs.error = str(exc)
            return obs
        try:
            obs.consistency = self.ripestat.prefix_routing_consistency(target.resource)
        except SourceError as exc:
            log.info("%s : prefix-routing-consistency indisponible (%s)", target.label, exc)
        if self.settings.rpki.enabled:
            pairs: set[tuple[str, int]] = set()
            for r in obs.routes:
                if not r.as_path or prefix_relation(r.prefix, target.network) == "less":
                    continue
                last_hop = strip_prepends(r.as_path)[-1]
                if isinstance(last_hop, int):
                    pairs.add((r.prefix, last_hop))
            try:
                obs.rpki = {
                    (p, o): self.ripestat.rpki_validation(o, p).to_dict() for p, o in sorted(pairs)
                }
            except SourceError as exc:
                obs.rpki_error = str(exc)
        return obs

    def collect_asn(self, target: Target) -> AsnObservation:
        obs = AsnObservation(target)
        try:
            obs.prefixes = self.ripestat.announced_prefixes(
                target.asn, self.settings.ripestat.asn_prefix_window_hours
            )
        except SourceError as exc:
            obs.error = str(exc)
            return obs
        if target.watch_neighbours:
            try:
                kept = self.settings.ripestat.neighbour_types
                obs.neighbours = {
                    asn: kind
                    for asn, kind in self.ripestat.asn_neighbours(target.asn).items()
                    if kind in kept
                }
            except SourceError as exc:
                obs.neighbours_error = str(exc)
        return obs

    def collect_irr(self, target: Target) -> IrrObservation | None:
        if self.irr is None or target.irr != "watch":
            return None
        return IrrObservation(target, self.irr.fetch(target))

    # ── Traitement (thread unique) ────────────────────────────────────────
    def _ctx(self, target: Target) -> RuleContext:
        return RuleContext(
            baseline_done=self.state.get_snapshot("baseline", target.label) is not None,
            learned_upstreams=lambda origin: self.state.learned_upstreams(target.label, origin),
            severity_overrides=self.settings.severity_overrides,
            now=iso(),
        )

    def _source_check(self, label: str, source: str, error: str | None) -> list[Event]:
        """Met à jour la santé d'une source et la condition SOURCE_ERROR associée."""
        ctx = RuleContext(severity_overrides=self.settings.severity_overrides)
        if error is None:
            self.state.source_success(label, source)
            return self.state.reconcile(label, source, [], {"SOURCE_ERROR"})
        failures = self.state.source_failure(label, source, error)
        log.warning("%s : source %s en échec (%d) : %s", label, source, failures, error)
        if failures < self.settings.source_error_cycles:
            return []
        ev = source_error_event(label, source, failures, error, ctx)
        return self.state.reconcile(label, source, [ev], {"SOURCE_ERROR"})

    def _apply_routes(
        self, target: Target, routes: list[Route], source: str, scope_prefix: str | None
    ) -> list[Event]:
        ctx = self._ctx(target)
        result = evaluate_routes(target, routes, ctx, source)
        stateful = [e for e in result.events if e.stateful]
        oneshot = [e for e in result.events if not e.stateful]
        out = self.state.reconcile(target.label, source, stateful, ROUTE_EVENT_TYPES, scope_prefix)
        out += self.state.record_oneshot(oneshot)
        self.state.learn_upstreams(target.label, result.learned)
        return out

    def process(self, obs: Observation) -> list[Event]:
        if isinstance(obs, PrefixObservation):
            events = self._process_prefix(obs)
        elif isinstance(obs, AsnObservation):
            events = self._process_asn(obs)
        else:
            events = self._process_irr(obs)
        self.dispatcher.dispatch(events)
        self.refresh_state(obs.target)
        return events

    def _process_prefix(self, obs: PrefixObservation) -> list[Event]:
        t = obs.target
        events = self._source_check(t.label, "ripestat", obs.error)
        if obs.error is not None or obs.status is None:
            return events  # aucune condition n'est résolue sur la base d'une erreur
        events += self._apply_routes(t, obs.routes, "ripestat", None)
        self.state.set_snapshot("baseline", t.label, {"ts": iso()})

        ctx = self._ctx(t)
        baseline = self.state.get_snapshot("visibility", t.label)
        vis_events, new_baseline = evaluate_visibility(
            t,
            obs.status.peers_seeing,
            obs.status.total_peers,
            baseline.get("baseline") if baseline else None,
            self.settings.visibility_drop_pct,
            ctx,
            "ripestat",
        )
        events += self.state.reconcile(t.label, "ripestat", vis_events, {"VISIBILITY_DROP"})
        self.state.set_snapshot(
            "visibility",
            t.label,
            {
                "baseline": new_baseline,
                "seeing": obs.status.peers_seeing,
                "total": obs.status.total_peers,
            },
        )

        if self.settings.rpki.enabled:
            events += self._source_check(t.label, "rpki", obs.rpki_error)
            if obs.rpki is not None:
                previous = self.state.get_snapshot("rpki", t.label)
                rpki_events, snapshot = evaluate_rpki(t, obs.rpki, previous, ctx)
                events += self.state.reconcile(
                    t.label,
                    "rpki",
                    [e for e in rpki_events if e.stateful],
                    {"RPKI_INVALID", "RPKI_UNKNOWN"},
                )
                events += self.state.record_oneshot([e for e in rpki_events if not e.stateful])
                self.state.set_snapshot("rpki", t.label, snapshot)

        self.state.set_snapshot(
            "observation",
            t.label,
            {
                "routes": len(obs.routes),
                "origins": sorted(obs.status.origins),
                "more_specifics": [list(p) for p in obs.status.more_specifics],
                "less_specifics": [list(p) for p in obs.status.less_specifics],
                "peers_seeing": obs.status.peers_seeing,
                "total_peers": obs.status.total_peers,
                "truncated": obs.truncated,
                "consistency": obs.consistency,
                "first_seen": obs.status.first_seen,
                "last_seen": obs.status.last_seen,
            },
        )
        return events

    def _process_asn(self, obs: AsnObservation) -> list[Event]:
        t = obs.target
        events = self._source_check(t.label, "ripestat", obs.error)
        if obs.error is not None or obs.prefixes is None:
            return events
        ctx = self._ctx(t)
        if t.watch_prefix_set:
            previous = self.state.get_snapshot("asn_prefixes", t.label)
            if previous is not None:
                diff = diff_prefix_set(t, set(previous), obs.prefixes, ctx, "ripestat")
                events += self.state.record_oneshot(diff)
            self.state.set_snapshot("asn_prefixes", t.label, sorted(obs.prefixes))
        if t.watch_neighbours:
            events += self._source_check(t.label, "ripestat:neighbours", obs.neighbours_error)
            if obs.neighbours is not None:
                previous_nb = self.state.get_snapshot("asn_neighbours", t.label)
                if previous_nb is not None:
                    old = {int(k): v for k, v in previous_nb.items()}
                    events += self.state.record_oneshot(
                        diff_neighbours(t, old, obs.neighbours, ctx, "ripestat")
                    )
                self.state.set_snapshot(
                    "asn_neighbours", t.label, {str(k): v for k, v in obs.neighbours.items()}
                )
        self.state.set_snapshot("observation", t.label, {"prefix_count": len(obs.prefixes)})
        self.state.set_snapshot("baseline", t.label, {"ts": iso()})
        return events

    def _process_irr(self, obs: IrrObservation) -> list[Event]:
        t = obs.target
        ctx = self._ctx(t)
        events: list[Event] = []
        for server in [s.name for s in self.settings.irr.servers]:
            source = f"irr:{server}"
            error = obs.fetch.errors.get(server)
            events += self._source_check(t.label, source, error)
            current = obs.fetch.objects.get(server)
            if error is not None or current is None:
                continue  # un serveur en erreur ne doit pas faire croire à des suppressions
            previous = self.state.get_snapshot(f"irr:{server}", t.label)
            if previous is not None:
                changes = diff_objects(previous, current)
                events += self.state.record_oneshot(
                    irr_events(t, server, changes, changed_attributes, ctx)
                )
            self.state.set_snapshot(f"irr:{server}", t.label, current)
        return events

    # ── RIS Live ──────────────────────────────────────────────────────────
    def handle_live_update(self, upd: RouteUpdate) -> list[Event]:
        events: list[Event] = []
        concerned = [
            t
            for t in self.config.prefix_targets
            if prefix_relation(upd.prefix, self._networks[t.label]) is not None
        ]
        if concerned:
            ts = datetime.fromtimestamp(upd.timestamp, tz=timezone.utc).isoformat(
                timespec="seconds"
            )
            self.state.rib_apply(
                upd.collector or "?",
                upd.peer,
                upd.prefix,
                None if upd.withdrawn else path_to_json(upd.as_path),
                ts,
            )
            routes = self.state.rib_routes(upd.prefix)
            for t in concerned:
                events += self._apply_routes(t, routes, "ris_live", upd.prefix)
        if not upd.withdrawn and upd.as_path:
            origin = strip_prepends(upd.as_path)[-1]
            for t in self.config.asn_targets:
                if not (t.ris_live_origin and t.watch_prefix_set and origin == t.asn):
                    continue
                known = self.state.get_snapshot("asn_prefixes", t.label)
                if known is None or upd.prefix in known:
                    continue
                ctx = self._ctx(t)
                new_events = diff_prefix_set(
                    t, set(known), set(known) | {upd.prefix}, ctx, "ris_live"
                )
                for ev in new_events:
                    ev.as_path = path_to_json(upd.as_path)
                    ev.peer = upd.peer
                events += self.state.record_oneshot(new_events)
                self.state.set_snapshot("asn_prefixes", t.label, sorted({*known, upd.prefix}))
        if events:
            self.dispatcher.dispatch(events)
            labels = {e.target for e in events}
            for t in self.config.targets:
                if t.label in labels:
                    self.refresh_state(t)
        return events

    def handle_live_status(self, status: str, detail: str | None) -> list[Event]:
        """Connexion RIS Live : SOURCE_ERROR global après N déconnexions consécutives."""
        if status == "connected":
            events = self._source_check(GLOBAL_TARGET, "ris_live", None)
        elif status in ("disconnected", "error"):
            events = self._source_check(GLOBAL_TARGET, "ris_live", detail or status)
        else:
            return []
        self.dispatcher.dispatch(events)
        return events

    # ── État dérivé ───────────────────────────────────────────────────────
    def _has_data(self, target: Target) -> bool:
        observation = self.state.get_snapshot("observation", target.label)
        if not target.is_prefix:
            return observation is not None
        if observation and observation.get("routes"):
            return True
        net = self._networks[target.label]
        return any(prefix_relation(p, net) for p in self.state.rib_prefixes())

    def refresh_state(self, target: Target) -> str:
        health = self.state.source_health(target.label)
        core_failing = any(h["failures"] > 0 and h["source"] in CORE_SOURCES for h in health)
        state, reason = derive_state(
            self.state.active_conditions(target.label),
            self.state.recent_oneshots(target.label, self.settings.recent_window_hours),
            core_failing,
            self._has_data(target),
            target.expect_silent,
        )
        previous = self.state.set_target_state(target.label, state, reason)
        if previous is not None:
            log.info("%s : état %s → %s (%s)", target.label, previous, state, reason)
        return state

    def refresh_all(self) -> dict[str, str]:
        return {t.label: self.refresh_state(t) for t in self.config.targets}

    def run_cycle(self, include_irr: bool) -> list[Event]:
        """Un passage complet et synchrone (utilisé par `once`)."""
        events: list[Event] = []
        for t in self.config.targets:
            log.info("Vérification de %s", t.label)
            events += self.process(self.collect(t))
        if include_irr:
            for t in self.config.targets:
                irr_obs = self.collect_irr(t)
                if irr_obs is not None:
                    events += self.process(irr_obs)
        self.refresh_all()
        return events
