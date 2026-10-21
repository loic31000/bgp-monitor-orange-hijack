from __future__ import annotations

import csv
import io
import json

from bgpmon.models import ROUTE_EVENT_TYPES, Event, make_key
from bgpmon.report import (
    build_report_data,
    events_to_csv,
    events_to_json,
    render_html,
    report_title,
)
from bgpmon.state import State
from tests.conftest import ORANGE_TARGET, make_config


def raise_condition(state: State, message: str = "origine interdite AS41128") -> None:
    ev = Event(
        type="ORIGIN_FORBIDDEN",
        severity="critical",
        target="90.98.0.0/15",
        source="ripestat",
        key=make_key("ORIGIN_FORBIDDEN", "90.98.0.0/15", "x"),
        message=message,
        stateful=True,
        prefix="90.98.0.0/15",
        origin=41128,
        as_path=[6939, 41128],
    )
    state.reconcile("90.98.0.0/15", "ripestat", [ev], ROUTE_EVENT_TYPES)


def test_clean_report_has_no_alert_banner_and_uses_config_refresh(state: State) -> None:
    cfg = make_config([ORANGE_TARGET], settings={"check_interval": 120})
    state.set_target_state("90.98.0.0/15", "OK", "aucune anomalie active")
    html = render_html(build_report_data(cfg, state))
    assert "<title>BGP Monitor — aucune alerte active</title>" in html
    assert 'class="banner alert"' not in html
    assert '<meta http-equiv="refresh" content="120">' in html
    assert "167.32.0.0/16" not in html  # plus de titre codé en dur


def test_alert_report_title_banner_and_timeline(state: State) -> None:
    cfg = make_config([ORANGE_TARGET], settings={"report": {"refresh_seconds": 45}})
    raise_condition(state)
    state.set_target_state("90.98.0.0/15", "ALERT", "ORIGIN_FORBIDDEN")
    data = build_report_data(cfg, state)
    html = render_html(data)
    assert report_title(data) == "BGP Monitor — 1 cible(s) en alerte"
    assert 'class="banner alert"' in html
    assert 'content="45"' in html
    assert "6939 41128" in html and "Chronologie (1 derniers événements)" in html


def test_unknown_targets_are_not_shown_as_clean(state: State) -> None:
    cfg = make_config([ORANGE_TARGET])
    data = build_report_data(cfg, state)  # jamais vérifiée
    assert data.targets[0].state == "UNKNOWN"
    assert report_title(data) == "BGP Monitor — 1 cible(s) en état inconnu"


def test_html_is_escaped(state: State) -> None:
    target = dict(ORANGE_TARGET, role="<script>alert(1)</script>", description='"&<b>')
    cfg = make_config([target])
    raise_condition(state, message="<img src=x onerror=alert(1)>")
    html = render_html(build_report_data(cfg, state))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html


def test_csv_and_json_exports(state: State) -> None:
    raise_condition(state, message='virgule, "guillemets"')
    events = state.query_events(limit=None)
    rows = list(csv.DictReader(io.StringIO(events_to_csv(events))))
    assert rows[0]["type"] == "ORIGIN_FORBIDDEN" and rows[0]["as_path"] == "6939 41128"
    assert rows[0]["message"] == 'virgule, "guillemets"'
    data = json.loads(events_to_json(events))
    assert data[0]["origin"] == 41128 and data[0]["phase"] == "raised"
