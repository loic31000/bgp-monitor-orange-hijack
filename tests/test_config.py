from __future__ import annotations

import copy
import ipaddress
import json
from pathlib import Path

import pytest

from bgpmon.config import (
    ConfigError,
    extract_legacy_default_config,
    load_config,
    load_legacy,
    migrate_legacy,
    parse_config,
)
from tests.conftest import ORANGE_TARGET, make_config

ROOT = Path(__file__).resolve().parents[1]


def test_example_config_is_valid_and_covers_v24_targets() -> None:
    cfg = load_config(ROOT / "config.example.yaml")
    labels = {t.label for t in cfg.targets}
    legacy = extract_legacy_default_config((ROOT / "legacy" / "bgp_monitor.py").read_text("utf-8"))
    # Les sous-préfixes 167.32.x sont couverts par la cible 167.32.0.0/16 (moreSpecific),
    # et 90.98.0.0/15 par ses deux moitiés /16, vérifiées ci-dessous.
    covered = {
        t["label"]
        for t in legacy["targets"]
        if (not t["label"].startswith("167.32.") or t["label"] == "167.32.0.0/16")
        and t["label"] != "90.98.0.0/15"
    }
    assert covered <= labels
    assert not any(lbl.startswith("167.32.") and lbl != "167.32.0.0/16" for lbl in labels)
    silent = [t.label for t in cfg.targets if t.expect_silent]
    assert silent == ["198.193.12.0/24", "198.195.144.0/24", "198.196.199.0/24"]
    # 90.98.0.0/15 (v2.4) : transféré pour moitié à Fastly le 03/09/2026, scindé en deux /16.
    fastly = cfg.target("90.98.0.0/16")
    orange = cfg.target("90.99.0.0/16")
    assert fastly is not None and orange is not None
    assert fastly.expected_origins == (54113,)
    assert {41128, 270118} <= set(fastly.forbidden_origins)
    assert orange.expected_origins == (3215,)
    assert {41128, 270118} <= set(orange.forbidden_origins)
    assert orange.rpki == "expect_valid"
    assert fastly.forbidden_path_asns == orange.forbidden_path_asns == (41128, 22541, 29802)
    halves = [ipaddress.IPv4Network(fastly.resource), ipaddress.IPv4Network(orange.resource)]
    assert list(ipaddress.collapse_addresses(halves)) == [ipaddress.IPv4Network("90.98.0.0/15")]
    assert cfg.settings.report_refresh == cfg.settings.check_interval


def test_example_config_has_no_webhook_url() -> None:
    text = (ROOT / "config.example.yaml").read_text("utf-8")
    assert "https://discord" not in text and "hooks.slack.com" not in text
    cfg = load_config(ROOT / "config.example.yaml")
    webhooks = [c for c in cfg.settings.alerts.channels if c.type == "webhook"]
    assert webhooks and all(c.url is None and c.url_env == "BGPMON_WEBHOOK_URL" for c in webhooks)


def test_targets_are_not_merged_with_hidden_defaults() -> None:
    cfg = make_config([ORANGE_TARGET])
    assert [t.label for t in cfg.targets] == ["90.98.0.0/15"]


def test_validation_collects_all_errors() -> None:
    bad = copy.deepcopy(ORANGE_TARGET)
    bad.update({"resource": "90.98.0.1/15", "severity": "fatal", "unknown_key": 1})
    with pytest.raises(ConfigError) as err:
        parse_config(
            {"version": 3, "targets": [bad, {"label": "x", "type": "asn", "resource": "ASxyz"}]}
        )
    text = str(err.value)
    assert "préfixe invalide" in text
    assert "fatal" in text
    assert "clé inconnue" in text
    assert "ASN invalide" in text


def test_rejects_wrong_version_and_type_specific_keys() -> None:
    with pytest.raises(ConfigError, match="migrate-config"):
        parse_config({"version": 2, "targets": [ORANGE_TARGET]})
    t = copy.deepcopy(ORANGE_TARGET)
    t["watch_neighbours"] = True
    with pytest.raises(ConfigError, match="réservé aux cibles de type asn"):
        parse_config({"version": 3, "targets": [t]})


def test_rejects_overlapping_expected_and_forbidden() -> None:
    t = copy.deepcopy(ORANGE_TARGET)
    t["forbidden_origins"] = [3215]
    with pytest.raises(ConfigError, match="attendu et interdit"):
        parse_config({"version": 3, "targets": [t]})


def test_duplicate_labels_and_reserved_label() -> None:
    with pytest.raises(ConfigError, match="double"):
        parse_config({"version": 3, "targets": [ORANGE_TARGET, ORANGE_TARGET]})
    t = copy.deepcopy(ORANGE_TARGET)
    t["label"] = "*"
    with pytest.raises(ConfigError, match="réservé"):
        parse_config({"version": 3, "targets": [t]})


def test_asn_accepts_as_prefix_string() -> None:
    cfg = make_config([{"label": "AS3215", "type": "asn", "resource": "AS3215"}])
    assert cfg.targets[0].asn == 3215


def test_json_config_supported(tmp_path: Path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"version": 3, "targets": [ORANGE_TARGET]}), "utf-8")
    assert load_config(path).targets[0].label == "90.98.0.0/15"


def test_migrate_legacy_json() -> None:
    legacy = load_legacy(ROOT / "legacy" / "config.v2.json")
    data, warnings = migrate_legacy({**legacy, "webhook_url": "https://example.invalid/hook"})
    cfg = parse_config(data)
    t = cfg.target("90.98.0.0/15")
    assert t is not None
    assert t.expected_origins == (3215,) and t.forbidden_origins == (41128,)
    assert t.severity == "critical"
    asn = cfg.target("AS41128")
    assert asn is not None and asn.type == "asn" and asn.asn == 41128
    assert cfg.settings.check_interval == 300
    assert "example.invalid" not in json.dumps(data)
    assert any("BGPMON_WEBHOOK_URL" in w for w in warnings)


def test_migrate_legacy_default_config_without_executing_script(tmp_path: Path) -> None:
    script = tmp_path / "bgp_monitor.py"
    script.write_text(
        "import os\nos.system('echo ne-doit-pas-s-executer')\n"
        "DEFAULT_CONFIG = {'refresh_seconds': 120, 'targets': [{'label': 'AS2702', "
        "'type': 'asn', 'resource': '2702', 'role': 'r', 'desc': 'd'}]}\n",
        "utf-8",
    )
    data, _ = migrate_legacy(load_legacy(script))
    cfg = parse_config(data)
    assert cfg.settings.check_interval == 120
    assert cfg.targets[0].asn == 2702


def test_migrate_full_legacy_script() -> None:
    data, _ = migrate_legacy(load_legacy(ROOT / "legacy" / "bgp_monitor.py"))
    cfg = parse_config(data)
    assert len(cfg.targets) == 20
    sub = cfg.target("167.32.2.0/24")
    assert sub is not None and sub.forbidden_origins == (398290,)


def test_expect_silent_validation() -> None:
    silent = {
        "label": "s",
        "type": "prefix",
        "resource": "198.51.100.0/24",
        "expect_silent": True,
        "forbidden_origins": [2702],
    }
    assert make_config([silent]).targets[0].expect_silent
    with pytest.raises(ConfigError, match="expect_silent"):
        parse_config({"version": 3, "targets": [dict(silent, expected_origins=[64500])]})
    with pytest.raises(ConfigError, match="réservé aux cibles de type prefix"):
        parse_config(
            {
                "version": 3,
                "targets": [{"label": "a", "type": "asn", "resource": 1, "expect_silent": True}],
            }
        )
