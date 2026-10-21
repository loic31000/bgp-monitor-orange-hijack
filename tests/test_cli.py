from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from bgpmon import cli
from bgpmon.config import load_config
from bgpmon.models import ROUTE_EVENT_TYPES, Event, make_key
from bgpmon.state import State
from tests.conftest import ORANGE_TARGET

ROOT = Path(__file__).resolve().parents[1]


def write_config(tmp_path: Path) -> Path:
    cfg = {
        "version": 3,
        "settings": {
            "db_path": str(tmp_path / "db.sqlite3"),
            "log_file": None,
            "report": {"path": str(tmp_path / "report.html")},
            "alerts": {"channels": []},
        },
        "targets": [ORANGE_TARGET],
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg), "utf-8")
    return path


def test_check_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check-config", "-c", str(ROOT / "config.example.yaml")]) == 0
    out = capsys.readouterr().out
    assert "Configuration valide" in out and "7 préfixe(s), 7 ASN" in out


def test_check_config_invalid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 3\ntargets: []\n", "utf-8")
    assert cli.main(["check-config", "-c", str(bad)]) == 1
    assert "au moins une cible" in capsys.readouterr().err


def test_migrate_config_writes_valid_yaml(tmp_path: Path) -> None:
    out = tmp_path / "migrated.yaml"
    assert (
        cli.main(["migrate-config", str(ROOT / "legacy" / "bgp_monitor.py"), "-o", str(out)]) == 0
    )
    assert len(load_config(out).targets) == 20
    # Pas d'écrasement sans --force.
    assert (
        cli.main(["migrate-config", str(ROOT / "legacy" / "config.v2.json"), "-o", str(out)]) == 1
    )
    assert (
        cli.main(
            ["migrate-config", str(ROOT / "legacy" / "config.v2.json"), "-o", str(out), "--force"]
        )
        == 0
    )
    assert len(load_config(out).targets) == 5


def test_report_and_events_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg_path = write_config(tmp_path)
    st = State(tmp_path / "db.sqlite3")
    st.reconcile(
        "90.98.0.0/15",
        "ripestat",
        [
            Event(
                type="ORIGIN_FORBIDDEN",
                severity="critical",
                target="90.98.0.0/15",
                source="ripestat",
                key=make_key("ORIGIN_FORBIDDEN", "90.98.0.0/15"),
                message="m",
                stateful=True,
                prefix="90.98.0.0/15",
            )
        ],
        ROUTE_EVENT_TYPES,
    )
    st.close()
    csv_path, json_path = tmp_path / "e.csv", tmp_path / "e.json"
    assert (
        cli.main(["report", "-c", str(cfg_path), "--csv", str(csv_path), "--json", str(json_path)])
        == 0
    )
    assert (tmp_path / "report.html").exists()
    assert json.loads(json_path.read_text("utf-8"))[0]["type"] == "ORIGIN_FORBIDDEN"
    assert cli.main(["events", "-c", str(cfg_path), "--severity", "high"]) == 0
    assert "ORIGIN_FORBIDDEN" in capsys.readouterr().out
    assert (
        cli.main(["events", "-c", str(cfg_path), "--type", "RPKI_INVALID", "--format", "json"]) == 0
    )
    assert json.loads(capsys.readouterr().out) == []


def test_exit_codes() -> None:
    assert cli._exit_code({"a": "OK", "b": "WARNING"}, False) == 0
    assert cli._exit_code({"a": "ALERT", "b": "UNKNOWN"}, False) == 2
    assert cli._exit_code({"a": "UNKNOWN"}, False) == 3
    assert cli._exit_code({"a": "UNKNOWN"}, True) == 0


def test_missing_config_hint(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check-config", "-c", str(tmp_path / "absent.yaml")]) == 1
    assert "config.example.yaml" in capsys.readouterr().err


def test_test_alert_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    alerts = tmp_path / "alerts.jsonl"
    cfg = {
        "version": 3,
        "settings": {
            "db_path": str(tmp_path / "db.sqlite3"),
            "log_file": None,
            "alerts": {
                "channels": [
                    {"type": "jsonl", "path": str(alerts)},
                    {"type": "webhook", "url_env": "BGPMON_WEBHOOK_URL"},
                ]
            },
        },
        "targets": [ORANGE_TARGET],
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg), "utf-8")
    monkeypatch.delenv("BGPMON_WEBHOOK_URL", raising=False)
    # Sans variable d'environnement, aucun canal webhook n'est actif.
    assert cli.main(["test-alert", "-c", str(path), "--channel", "webhook"]) == 1
    assert "BGPMON_WEBHOOK_URL" in capsys.readouterr().err
    assert cli.main(["test-alert", "-c", str(path)]) == 0
    assert "jsonl : envoyé" in capsys.readouterr().out
    record = json.loads(alerts.read_text("utf-8"))
    assert record["type"] == "TEST_ALERT" and "aucune action requise" in record["message"]
    # Rien n'est écrit dans l'historique des événements.
    st = State(tmp_path / "db.sqlite3")
    assert st.query_events() == []
    st.close()
