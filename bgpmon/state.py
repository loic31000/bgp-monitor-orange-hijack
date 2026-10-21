"""Persistance SQLite : conditions actives, historique, snapshots, RIB RIS Live.

Une condition (événement « stateful ») n'est enregistrée dans l'historique
qu'à son apparition (`raised`) et à sa disparition (`resolved`). Chaque
condition mémorise les sources qui la confirment : elle n'est résolue que
lorsque plus aucune source ne l'observe.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from bgpmon.models import (
    SEVERITY_RANK,
    Event,
    Route,
    iso,
    max_severity,
    normalize_path,
    utcnow,
)

log = logging.getLogger("bgpmon.state")

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, target TEXT NOT NULL,
    phase TEXT NOT NULL, source TEXT NOT NULL, key TEXT NOT NULL,
    prefix TEXT, origin INTEGER, as_path TEXT, peer TEXT,
    message TEXT NOT NULL, evidence TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_target_ts ON events (target, ts);
CREATE TABLE IF NOT EXISTS conditions (
    key TEXT PRIMARY KEY, target TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL,
    prefix TEXT, active INTEGER NOT NULL, sources TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT, event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS conditions_target ON conditions (target, active);
CREATE TABLE IF NOT EXISTS snapshots (
    kind TEXT NOT NULL, target TEXT NOT NULL, data TEXT NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY (kind, target)
);
CREATE TABLE IF NOT EXISTS learned_upstreams (
    target TEXT NOT NULL, origin INTEGER NOT NULL, upstream INTEGER NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY (target, origin, upstream)
);
CREATE TABLE IF NOT EXISTS source_health (
    target TEXT NOT NULL, source TEXT NOT NULL, failures INTEGER NOT NULL,
    last_error TEXT, last_ok TEXT, last_attempt TEXT NOT NULL,
    PRIMARY KEY (target, source)
);
CREATE TABLE IF NOT EXISTS rib (
    collector TEXT NOT NULL, peer TEXT NOT NULL, prefix TEXT NOT NULL,
    as_path TEXT NOT NULL, ts TEXT,
    PRIMARY KEY (collector, peer, prefix)
);
CREATE INDEX IF NOT EXISTS rib_prefix ON rib (prefix);
CREATE TABLE IF NOT EXISTS target_state (
    target TEXT PRIMARY KEY, state TEXT NOT NULL, reason TEXT NOT NULL,
    since TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts_sent (dedup_key TEXT PRIMARY KEY, sent_at REAL NOT NULL);
"""

STATES = ("OK", "WARNING", "ALERT", "UNKNOWN")
# Sources dont l'échec rend l'état d'une cible inconnu (et non simplement dégradé).
CORE_SOURCES = frozenset({"ripestat"})


def _event_from_row(row: sqlite3.Row) -> Event:
    return Event(
        id=row["id"],
        type=row["type"],
        severity=row["severity"],
        target=row["target"],
        source=row["source"],
        key=row["key"],
        message=row["message"],
        stateful=row["phase"] != "oneshot",
        phase=row["phase"],
        timestamp=row["ts"],
        prefix=row["prefix"],
        origin=row["origin"],
        as_path=json.loads(row["as_path"]) if row["as_path"] else None,
        peer=row["peer"],
        evidence=json.loads(row["evidence"]),
    )


class State:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        with self._tx():
            self.conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def close(self) -> None:
        try:
            self.conn.commit()
        finally:
            self.conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.conn
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    # ── Événements ──
    def _insert_event(self, ev: Event) -> int:
        cur = self.conn.execute(
            "INSERT INTO events (ts, type, severity, target, phase, source, key, prefix, origin,"
            " as_path, peer, message, evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                ev.timestamp,
                ev.type,
                ev.severity,
                ev.target,
                ev.phase,
                ev.source,
                ev.key,
                ev.prefix,
                ev.origin,
                json.dumps(ev.as_path) if ev.as_path is not None else None,
                ev.peer,
                ev.message,
                json.dumps(ev.evidence, ensure_ascii=False, default=str),
            ),
        )
        return int(cur.lastrowid or 0)

    def record_oneshot(self, events: Iterable[Event]) -> list[Event]:
        out: list[Event] = []
        with self._tx():
            for ev in events:
                ev = replace(ev, phase="oneshot", stateful=False)
                ev.id = self._insert_event(ev)
                out.append(ev)
        return out

    def reconcile(
        self,
        target: str,
        source: str,
        events: Iterable[Event],
        scope_types: Iterable[str],
        scope_prefix: str | None = None,
    ) -> list[Event]:
        """Applique l'observation complète d'une source sur un périmètre donné.

        `events` doit contenir toutes les conditions que `source` observe
        actuellement pour `target` dans le périmètre (`scope_types`, et
        `scope_prefix` s'il est fourni). Retourne les transitions (raised/resolved).
        """
        now = iso()
        current = {ev.key: ev for ev in events if ev.stateful}
        types = sorted(set(scope_types))
        transitions: list[Event] = []
        with self._tx():
            for key, ev in current.items():
                row = self.conn.execute(
                    "SELECT active, sources, severity FROM conditions WHERE key = ?", (key,)
                ).fetchone()
                if row is not None and row["active"]:
                    sources = sorted(set(json.loads(row["sources"])) | {source})
                    self.conn.execute(
                        "UPDATE conditions SET sources = ?, last_seen = ?, severity = ?"
                        " WHERE key = ?",
                        (json.dumps(sources), now, max_severity(row["severity"], ev.severity), key),
                    )
                    continue
                raised = replace(ev, phase="raised", source=source, timestamp=now)
                raised.id = self._insert_event(raised)
                self.conn.execute(
                    "INSERT OR REPLACE INTO conditions (key, target, type, severity, prefix,"
                    " active, sources, first_seen, last_seen, resolved_at, event)"
                    " VALUES (?,?,?,?,?,1,?,?,?,NULL,?)",
                    (
                        key,
                        target,
                        ev.type,
                        ev.severity,
                        ev.prefix,
                        json.dumps([source]),
                        now,
                        now,
                        json.dumps(raised.to_dict(), ensure_ascii=False, default=str),
                    ),
                )
                transitions.append(raised)

            sql = (
                "SELECT * FROM conditions WHERE target = ? AND active = 1 AND type IN "
                f"({','.join('?' * len(types))})"
            )
            params: list[Any] = [target, *types]
            if scope_prefix is not None:
                sql += " AND prefix = ?"
                params.append(scope_prefix)
            for row in self.conn.execute(sql, params).fetchall() if types else []:
                if row["key"] in current:
                    continue
                remaining = set(json.loads(row["sources"]))
                if source not in remaining:
                    continue
                remaining.discard(source)
                if remaining:
                    self.conn.execute(
                        "UPDATE conditions SET sources = ? WHERE key = ?",
                        (json.dumps(sorted(remaining)), row["key"]),
                    )
                    continue
                transitions.append(self._resolve(row, source, now))
        return transitions

    def _resolve(self, row: sqlite3.Row, source: str, now: str) -> Event:
        original = Event.from_dict(json.loads(row["event"]))
        duration = None
        with suppress(ValueError):
            started = datetime.fromisoformat(row["first_seen"])
            duration = int((datetime.fromisoformat(now) - started).total_seconds())
        evidence = {**original.evidence, "raised_at": row["first_seen"], "duration_s": duration}
        if original.type == "VISIBILITY_DROP":
            resolved = replace(
                original,
                type="VISIBILITY_RESTORED",
                severity="info",
                message=f"Visibilité rétablie pour {original.prefix}",
                evidence=evidence,
            )
        else:
            resolved = replace(original, message=f"Résolu : {original.message}", evidence=evidence)
        resolved = replace(resolved, phase="resolved", source=source, timestamp=now, id=None)
        resolved.id = self._insert_event(resolved)
        self.conn.execute(
            "UPDATE conditions SET active = 0, resolved_at = ?, sources = '[]' WHERE key = ?",
            (now, row["key"]),
        )
        return resolved

    def active_conditions(self, target: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM conditions WHERE active = 1"
        params: tuple[Any, ...] = ()
        if target is not None:
            sql += " AND target = ?"
            params = (target,)
        rows = self.conn.execute(sql + " ORDER BY first_seen", params).fetchall()
        return [
            {**dict(row), "sources": json.loads(row["sources"]), "event": json.loads(row["event"])}
            for row in rows
        ]

    def query_events(
        self,
        target: str | None = None,
        types: Iterable[str] | None = None,
        min_severity: str | None = None,
        since: str | None = None,
        phase: str | None = None,
        limit: int | None = 50,
    ) -> list[Event]:
        """Événements les plus récents d'abord."""
        clauses: list[str] = []
        params: list[Any] = []
        if target:
            clauses.append("target = ?")
            params.append(target)
        type_list = sorted(set(types or []))
        if type_list:
            clauses.append(f"type IN ({','.join('?' * len(type_list))})")
            params.extend(type_list)
        if min_severity:
            allowed = [s for s, r in SEVERITY_RANK.items() if r >= SEVERITY_RANK[min_severity]]
            clauses.append(f"severity IN ({','.join('?' * len(allowed))})")
            params.extend(allowed)
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if phase:
            clauses.append("phase = ?")
            params.append(phase)
        sql = "SELECT * FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [_event_from_row(r) for r in self.conn.execute(sql, params).fetchall()]

    # ── Snapshots (ensembles de préfixes, voisins, IRR, RPKI, visibilité…) ──
    def get_snapshot(self, kind: str, target: str) -> Any:
        row = self.conn.execute(
            "SELECT data FROM snapshots WHERE kind = ? AND target = ?", (kind, target)
        ).fetchone()
        return json.loads(row["data"]) if row else None

    def set_snapshot(self, kind: str, target: str, data: Any) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT OR REPLACE INTO snapshots (kind, target, data, updated_at)"
                " VALUES (?,?,?,?)",
                (kind, target, json.dumps(data, ensure_ascii=False, default=str), iso()),
            )

    def snapshot_time(self, kind: str, target: str) -> str | None:
        row = self.conn.execute(
            "SELECT updated_at FROM snapshots WHERE kind = ? AND target = ?", (kind, target)
        ).fetchone()
        return row["updated_at"] if row else None

    # ── Upstreams appris ──
    def learned_upstreams(self, target: str, origin: int) -> set[int]:
        rows = self.conn.execute(
            "SELECT upstream FROM learned_upstreams WHERE target = ? AND origin = ?",
            (target, origin),
        ).fetchall()
        return {int(r["upstream"]) for r in rows}

    def learn_upstreams(self, target: str, pairs: Iterable[tuple[int, int]]) -> None:
        now = iso()
        with self._tx():
            for origin, upstream in pairs:
                self.conn.execute(
                    "INSERT INTO learned_upstreams"
                    " (target, origin, upstream, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?) ON CONFLICT (target, origin, upstream)"
                    " DO UPDATE SET last_seen = excluded.last_seen",
                    (target, origin, upstream, now, now),
                )

    # ── Santé des sources ──
    def source_failure(self, target: str, source: str, error: str) -> int:
        now = iso()
        with self._tx():
            self.conn.execute(
                "INSERT INTO source_health (target, source, failures, last_error, last_attempt)"
                " VALUES (?,?,1,?,?) ON CONFLICT (target, source) DO UPDATE SET"
                " failures = failures + 1, last_error = excluded.last_error,"
                " last_attempt = excluded.last_attempt",
                (target, source, error, now),
            )
        row = self.conn.execute(
            "SELECT failures FROM source_health WHERE target = ? AND source = ?", (target, source)
        ).fetchone()
        return int(row["failures"])

    def source_success(self, target: str, source: str) -> None:
        now = iso()
        with self._tx():
            self.conn.execute(
                "INSERT INTO source_health (target, source, failures, last_ok, last_attempt)"
                " VALUES (?,?,0,?,?) ON CONFLICT (target, source) DO UPDATE SET"
                " failures = 0, last_ok = excluded.last_ok, last_attempt = excluded.last_attempt",
                (target, source, now, now),
            )

    def source_health(self, target: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM source_health"
        params: tuple[Any, ...] = ()
        if target is not None:
            sql += " WHERE target = ?"
            params = (target,)
        return [dict(r) for r in self.conn.execute(sql + " ORDER BY target, source", params)]

    # ── RIB construite à partir de RIS Live ──
    def rib_apply(
        self, collector: str, peer: str, prefix: str, as_path: list[Any] | None, ts: str
    ) -> None:
        """Annonce (as_path) ou retrait (None) ; une annonce remplace la précédente."""
        with self._tx():
            if as_path is None:
                self.conn.execute(
                    "DELETE FROM rib WHERE collector = ? AND peer = ? AND prefix = ?",
                    (collector, peer, prefix),
                )
            else:
                self.conn.execute(
                    "INSERT OR REPLACE INTO rib (collector, peer, prefix, as_path, ts)"
                    " VALUES (?,?,?,?,?)",
                    (collector, peer, prefix, json.dumps(as_path), ts),
                )

    def rib_routes(self, prefix: str) -> list[Route]:
        rows = self.conn.execute("SELECT * FROM rib WHERE prefix = ?", (prefix,)).fetchall()
        return [
            Route(
                prefix=r["prefix"],
                peer=r["peer"],
                as_path=normalize_path(json.loads(r["as_path"])),
                source="ris_live",
                collector=r["collector"],
                timestamp=r["ts"],
            )
            for r in rows
        ]

    def rib_prefixes(self) -> list[str]:
        return [r["prefix"] for r in self.conn.execute("SELECT DISTINCT prefix FROM rib")]

    # ── État dérivé des cibles ──
    def set_target_state(self, target: str, state: str, reason: str) -> str | None:
        """Enregistre l'état ; retourne l'ancien état s'il a changé."""
        now = iso()
        row = self.conn.execute(
            "SELECT state FROM target_state WHERE target = ?", (target,)
        ).fetchone()
        previous = row["state"] if row else None
        with self._tx():
            if previous == state:
                self.conn.execute(
                    "UPDATE target_state SET reason = ?, updated_at = ? WHERE target = ?",
                    (reason, now, target),
                )
            else:
                self.conn.execute(
                    "INSERT OR REPLACE INTO target_state (target, state, reason, since, updated_at)"
                    " VALUES (?,?,?,?,?)",
                    (target, state, reason, now, now),
                )
        return previous if previous != state else None

    def target_states(self) -> dict[str, dict[str, Any]]:
        return {r["target"]: dict(r) for r in self.conn.execute("SELECT * FROM target_state")}

    def recent_oneshots(self, target: str, hours: int) -> list[Event]:
        since = iso(utcnow() - timedelta(hours=hours))
        return self.query_events(target=target, since=since, phase="oneshot", limit=None)

    # ── Déduplication des alertes ──
    def alert_last_sent(self, dedup_key: str) -> float | None:
        row = self.conn.execute(
            "SELECT sent_at FROM alerts_sent WHERE dedup_key = ?", (dedup_key,)
        ).fetchone()
        return float(row["sent_at"]) if row else None

    def mark_alert_sent(self, dedup_key: str, sent_at: float) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT OR REPLACE INTO alerts_sent (dedup_key, sent_at) VALUES (?, ?)",
                (dedup_key, sent_at),
            )


def derive_state(
    active: list[dict[str, Any]],
    recent_oneshots: list[Event],
    core_failing: bool,
    has_data: bool,
    expect_silent: bool = False,
) -> tuple[str, str]:
    """État d'une cible. Une absence de données ou une source en erreur donne
    UNKNOWN, jamais OK, sauf pour une cible `expect_silent` dont la source répond :
    le silence y est l'état attendu. ALERT reste prioritaire si une autre source
    confirme un problème."""
    worst = "info"
    reasons: list[str] = []
    source_error_core = False
    for cond in active:
        if cond["type"] == "SOURCE_ERROR" and set(cond["sources"]) & CORE_SOURCES:
            source_error_core = True
            continue
        worst = max_severity(worst, cond["severity"])
        reasons.append(cond["type"])
    for ev in recent_oneshots:
        if ev.severity != "info":
            worst = max_severity(worst, ev.severity)
            reasons.append(ev.type)
    summary = ", ".join(sorted(set(reasons)))
    if SEVERITY_RANK[worst] >= SEVERITY_RANK["high"]:
        return "ALERT", summary
    if core_failing or source_error_core:
        return "UNKNOWN", "source RIPEstat en erreur : état non vérifiable"
    if not has_data:
        if expect_silent:
            return "OK", "OK-silencieux : aucune annonce, comme attendu"
        return "UNKNOWN", "aucune donnée de routage observée"
    if worst == "warning":
        return "WARNING", summary
    return "OK", "aucune anomalie active"
