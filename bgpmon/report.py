"""Rapport HTML autonome, résumé console et exports CSV/JSON des événements."""

from __future__ import annotations

import csv
import io
import json
import os
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from typing import Any

from bgpmon import __version__
from bgpmon.config import Config
from bgpmon.models import (
    EVENT_LABELS,
    GLOBAL_TARGET,
    SEVERITY_LABELS,
    Event,
    format_path,
    iso,
)
from bgpmon.state import State

STATE_LABELS = {"OK": "OK", "WARNING": "AVERTISSEMENT", "ALERT": "ALERTE", "UNKNOWN": "INCONNU"}
STATE_ORDER = {"ALERT": 0, "UNKNOWN": 1, "WARNING": 2, "OK": 3}
PHASE_LABELS = {"raised": "apparition", "resolved": "résolution", "oneshot": "changement"}


@dataclass
class TargetRow:
    label: str
    type: str
    resource: str
    role: str
    description: str
    state: str
    reason: str
    since: str | None
    conditions: list[dict[str, Any]] = field(default_factory=list)
    history: list[Event] = field(default_factory=list)


@dataclass
class ReportData:
    generated_at: str
    refresh_seconds: int
    targets: list[TargetRow]
    timeline: list[Event]
    sources: list[dict[str, Any]]

    def count(self, state: str) -> int:
        return sum(1 for t in self.targets if t.state == state)


def build_report_data(config: Config, state: State) -> ReportData:
    states = state.target_states()
    rows: list[TargetRow] = []
    rs = config.settings.report
    for t in config.targets:
        st = states.get(t.label)
        rows.append(
            TargetRow(
                label=t.label,
                type=t.type,
                resource=t.resource if t.is_prefix else f"AS{t.resource}",
                role=t.role,
                description=t.description,
                state=st["state"] if st else "UNKNOWN",
                reason=st["reason"] if st else "jamais vérifiée",
                since=st["since"] if st else None,
                conditions=state.active_conditions(t.label),
                history=state.query_events(target=t.label, limit=rs.history_per_target),
            )
        )
    return ReportData(
        generated_at=iso(),
        refresh_seconds=config.settings.report_refresh,
        targets=rows,
        timeline=state.query_events(limit=rs.timeline_size),
        sources=state.source_health(),
    )


def report_title(data: ReportData) -> str:
    alerts, unknown, warnings = data.count("ALERT"), data.count("UNKNOWN"), data.count("WARNING")
    if alerts:
        return f"BGP Monitor — {alerts} cible(s) en alerte"
    if unknown:
        return f"BGP Monitor — {unknown} cible(s) en état inconnu"
    if warnings:
        return f"BGP Monitor — {warnings} cible(s) en avertissement"
    return "BGP Monitor — aucune alerte active"


_CSS = """
:root{--bg:#0e1116;--panel:#161b22;--line:#2a313c;--text:#e6edf3;--muted:#8b949e;
--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--alert:#f85149;--unknown:#8b949e;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px 16px}
main{max-width:1280px;margin:0 auto}h1{font-size:1.4em;margin:0 0 4px}
h2{font-size:1.1em;margin:28px 0 10px;color:var(--accent)}
.sub{color:var(--muted);font-size:.85em;margin-bottom:18px}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:1px 10px;margin:2px 4px 2px 0}
.banner{border-radius:8px;padding:12px 16px;margin:12px 0;font-weight:600}
.banner.alert{background:rgba(248,81,73,.15);border:1px solid var(--alert)}
.banner.unknown{background:rgba(139,148,158,.12);border:1px solid var(--unknown)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;background:var(--panel)}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:.75em;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
tr:last-child td{border-bottom:none}code{font:12px ui-monospace,Consolas,monospace}
.badge{display:inline-block;border-radius:4px;padding:1px 8px;font-weight:700;font-size:.8em;color:#0e1116}
.s-OK{background:var(--ok)}.s-WARNING{background:var(--warn)}.s-ALERT{background:var(--alert)}
.s-UNKNOWN{background:var(--unknown)}
.v-info{color:var(--muted)}.v-warning{color:var(--warn)}.v-high,.v-critical{color:var(--alert);font-weight:600}
.muted{color:var(--muted)}ul{margin:0;padding-left:18px}
details{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:6px 0;padding:6px 12px}
summary{cursor:pointer}footer{margin-top:28px;color:var(--muted);font-size:.8em}
"""


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _event_rows(events: list[Event], with_target: bool) -> str:
    if not events:
        cols = 6 if with_target else 5
        return f'<tr><td colspan="{cols}" class="muted">Aucun événement enregistré.</td></tr>'
    rows = []
    for ev in events:
        target_cell = f"<td>{_e(ev.target)}</td>" if with_target else ""
        sev = "résolu" if ev.phase == "resolved" else SEVERITY_LABELS.get(ev.severity, ev.severity)
        rows.append(
            "<tr>"
            f"<td><code>{_e(ev.timestamp)}</code></td>{target_cell}"
            f'<td class="v-{_e(ev.severity)}">{_e(sev)}</td>'
            f'<td>{_e(EVENT_LABELS.get(ev.type, ev.type))}<br><code class="muted">{_e(ev.type)}</code>'
            f' <span class="muted">({_e(PHASE_LABELS.get(ev.phase, ev.phase))})</span></td>'
            f"<td>{_e(ev.message)}"
            + (
                f'<br><code class="muted">{_e(format_path(ev.as_path))}</code>'
                if ev.as_path
                else ""
            )
            + f"</td><td>{_e(ev.source)}</td></tr>"
        )
    return "".join(rows)


def render_html(data: ReportData) -> str:
    title = report_title(data)
    alerts = [t for t in data.targets if t.state == "ALERT"]
    unknown = [t for t in data.targets if t.state == "UNKNOWN"]
    banner = ""
    if alerts:
        items = "".join(f"<li>{_e(t.label)} — {_e(t.reason)}</li>" for t in alerts)
        banner = f'<div class="banner alert">{len(alerts)} cible(s) en alerte<ul>{items}</ul></div>'
    elif unknown:
        banner = (
            f'<div class="banner unknown">{len(unknown)} cible(s) sans donnée fiable : '
            "leur état n'est pas vérifié.</div>"
        )

    target_rows = []
    for t in sorted(data.targets, key=lambda r: (STATE_ORDER.get(r.state, 9), r.label)):
        conds = "".join(
            f'<li class="v-{_e(c["severity"])}">{_e(c["event"].get("message", c["type"]))}'
            f' <span class="muted">depuis {_e(c["first_seen"])} · {_e(", ".join(c["sources"]))}'
            "</span></li>"
            for c in t.conditions
        )
        target_rows.append(
            "<tr>"
            f'<td><strong>{_e(t.label)}</strong><br><code class="muted">{_e(t.resource)}</code></td>'
            f'<td>{_e(t.role)}<br><span class="muted">{_e(t.description)}</span></td>'
            f'<td><span class="badge s-{_e(t.state)}">{_e(STATE_LABELS.get(t.state, t.state))}</span>'
            f'<br><span class="muted">{_e(t.reason)}</span></td>'
            f"<td>{f'<ul>{conds}</ul>' if conds else '<span class=muted>—</span>'}</td>"
            f'<td><code class="muted">{_e(t.since or "—")}</code></td>'
            "</tr>"
        )

    source_rows = (
        "".join(
            "<tr>"
            f"<td>{_e('global' if s['target'] == GLOBAL_TARGET else s['target'])}</td>"
            f"<td>{_e(s['source'])}</td>"
            f'<td class="{"v-high" if s["failures"] else "v-info"}">{_e(s["failures"])}</td>'
            f"<td><code>{_e(s['last_ok'] or '—')}</code></td>"
            f"<td>{_e(s['last_error'] or '—') if s['failures'] else '—'}</td>"
            "</tr>"
            for s in data.sources
            if s["failures"]
        )
        or '<tr><td colspan="5" class="muted">Toutes les sources ont répondu au dernier passage.</td></tr>'
    )

    history = "".join(
        f"<details><summary><strong>{_e(t.label)}</strong> "
        f'<span class="badge s-{_e(t.state)}">{_e(STATE_LABELS.get(t.state, t.state))}</span> '
        f'<span class="muted">{len(t.history)} événement(s) récent(s)</span></summary>'
        '<div class="wrap"><table><thead><tr><th>Horodatage</th><th>Sévérité</th><th>Type</th>'
        f"<th>Détail</th><th>Source</th></tr></thead><tbody>{_event_rows(t.history, False)}"
        "</tbody></table></div></details>"
        for t in data.targets
    )

    counts = " ".join(
        f'<span class="pill">{_e(STATE_LABELS[s])} : {data.count(s)}</span>'
        for s in ("ALERT", "UNKNOWN", "WARNING", "OK")
    )
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{int(data.refresh_seconds)}">
<title>{_e(title)}</title>
<style>{_CSS}</style>
</head>
<body><main>
<h1>{_e(title)}</h1>
<p class="sub"><span class="pill">Généré le {_e(data.generated_at)}</span>
<span class="pill">Rafraîchissement : {int(data.refresh_seconds)} s</span>{counts}</p>
{banner}
<h2>Cibles</h2>
<div class="wrap"><table><thead><tr><th>Cible</th><th>Rôle</th><th>État</th>
<th>Conditions actives</th><th>Depuis</th></tr></thead>
<tbody>{"".join(target_rows)}</tbody></table></div>
<h2>Sources en erreur</h2>
<div class="wrap"><table><thead><tr><th>Cible</th><th>Source</th><th>Échecs consécutifs</th>
<th>Dernier succès</th><th>Dernière erreur</th></tr></thead><tbody>{source_rows}</tbody></table></div>
<h2>Chronologie ({len(data.timeline)} derniers événements)</h2>
<div class="wrap"><table><thead><tr><th>Horodatage</th><th>Cible</th><th>Sévérité</th><th>Type</th>
<th>Détail</th><th>Source</th></tr></thead><tbody>{_event_rows(data.timeline, True)}</tbody></table></div>
<h2>Historique par cible</h2>
{history}
<footer>bgpmon v{_e(__version__)} · sources publiques : RIPEstat, RIS Live, RPKI (RIPEstat), IRR (whois).
Un état ALERTE est une détection par règles, pas une attribution.</footer>
</main></body>
</html>
"""


def write_text_atomic(path: str | Path, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, p)


def write_report(config: Config, state: State, path: str | None = None) -> str:
    out = path or config.settings.report.path
    write_text_atomic(out, render_html(build_report_data(config, state)))
    return out


CSV_FIELDS = (
    "id",
    "timestamp",
    "type",
    "phase",
    "severity",
    "target",
    "prefix",
    "origin",
    "as_path",
    "peer",
    "source",
    "message",
    "evidence",
)


def events_to_csv(events: list[Event]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_FIELDS)
    for ev in events:
        writer.writerow(
            [
                ev.id,
                ev.timestamp,
                ev.type,
                ev.phase,
                ev.severity,
                ev.target,
                ev.prefix or "",
                "" if ev.origin is None else ev.origin,
                format_path(ev.as_path) if ev.as_path else "",
                ev.peer or "",
                ev.source,
                ev.message,
                json.dumps(ev.evidence, ensure_ascii=False, default=str),
            ]
        )
    return buf.getvalue()


def events_to_json(events: list[Event]) -> str:
    return json.dumps([ev.to_dict() for ev in events], ensure_ascii=False, indent=2, default=str)


def events_to_table(events: list[Event]) -> str:
    if not events:
        return "Aucun événement."
    lines = []
    for ev in events:
        sev = "résolu" if ev.phase == "resolved" else ev.severity
        lines.append(f"{ev.timestamp}  {sev:<8}  {ev.type:<26} {ev.target:<18} {ev.message}")
    return "\n".join(lines)


def render_summary(data: ReportData) -> str:
    lines = [report_title(data), ""]
    for t in sorted(data.targets, key=lambda r: (STATE_ORDER.get(r.state, 9), r.label)):
        lines.append(f"  {STATE_LABELS.get(t.state, t.state):<13} {t.label:<20} {t.reason}")
    return "\n".join(lines)
