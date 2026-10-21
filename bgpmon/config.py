"""Chargement, validation et migration de la configuration.

Le fichier de configuration (YAML ou JSON) est la seule source de vérité pour
les cibles. Les valeurs par défaut des réglages techniques sont documentées
dans `config.example.yaml` et dans le README ; aucune cible n'est codée en dur.
"""

from __future__ import annotations

import ast
import ipaddress
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bgpmon.models import EVENT_TYPES, GLOBAL_TARGET, SEVERITIES, Network, parse_asn

CONFIG_VERSION = 3
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
WEBHOOK_FORMATS = ("auto", "discord", "slack", "ntfy", "generic")


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("Configuration invalide :\n  - " + "\n  - ".join(errors))


# ── Modèle ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RipestatSettings:
    base_url: str = "https://stat.ripe.net/data"
    sourceapp: str = "bgpmon"
    timeout: float = 20.0
    retries: int = 3
    backoff: float = 2.0
    min_interval: float = 0.5
    cache_ttl: int = 60
    asn_prefix_window_hours: int = 24
    max_more_specific_queries: int = 32
    # Types asn-neighbours comparés ; « uncertain » fluctue beaucoup d'un jeu de données à l'autre.
    neighbour_types: tuple[str, ...] = ("left", "right")


@dataclass(frozen=True)
class RisLiveSettings:
    enabled: bool = True
    url: str = "wss://ris-live.ripe.net/v1/ws/?client=bgpmon-orange-investigation"
    heartbeat_seconds: int = 30
    reconnect_max_seconds: int = 300
    queue_size: int = 10000


@dataclass(frozen=True)
class IrrServer:
    name: str
    host: str
    port: int = 43
    query_prefix: str = ""


@dataclass(frozen=True)
class IrrSettings:
    enabled: bool = True
    interval: int = 3600
    timeout: float = 20.0
    query_delay: float = 1.0
    servers: tuple[IrrServer, ...] = ()


@dataclass(frozen=True)
class RpkiSettings:
    enabled: bool = True


@dataclass(frozen=True)
class ReportSettings:
    path: str = "bgp_report.html"
    refresh_seconds: int | None = None
    history_per_target: int = 20
    timeline_size: int = 50


@dataclass(frozen=True)
class AlertChannelConfig:
    type: str
    min_severity: str = "info"
    path: str | None = None
    url: str | None = None
    url_env: str | None = None
    format: str = "auto"
    timeout: float = 10.0


@dataclass(frozen=True)
class AlertSettings:
    cooldown_seconds: dict[str, int] = field(default_factory=lambda: {"default": 3600})
    channels: tuple[AlertChannelConfig, ...] = ()

    def cooldown_for(self, event_type: str) -> int:
        return self.cooldown_seconds.get(event_type, self.cooldown_seconds.get("default", 3600))


@dataclass(frozen=True)
class Settings:
    check_interval: int = 300
    log_level: str = "INFO"
    log_format: str = "text"
    log_file: str | None = "bgpmon.log"
    db_path: str = "bgpmon.sqlite3"
    recent_window_hours: int = 24
    source_error_cycles: int = 3
    visibility_drop_pct: float = 30.0
    severity_overrides: dict[str, str] = field(default_factory=dict)
    ripestat: RipestatSettings = field(default_factory=RipestatSettings)
    ris_live: RisLiveSettings = field(default_factory=RisLiveSettings)
    rpki: RpkiSettings = field(default_factory=RpkiSettings)
    irr: IrrSettings = field(default_factory=IrrSettings)
    report: ReportSettings = field(default_factory=ReportSettings)
    alerts: AlertSettings = field(default_factory=AlertSettings)

    @property
    def report_refresh(self) -> int:
        return self.report.refresh_seconds or self.check_interval


@dataclass(frozen=True)
class Target:
    label: str
    type: str  # prefix | asn
    resource: str  # préfixe normalisé, ou ASN en texte
    role: str = ""
    description: str = ""
    severity: str = "high"
    irr: str = "ignore"
    # Cibles préfixe
    expected_origins: tuple[int, ...] = ()
    forbidden_origins: tuple[int, ...] = ()
    forbidden_path_asns: tuple[int, ...] = ()
    expected_upstreams: tuple[int, ...] = ()
    max_prefix_length: int | None = None
    allow_more_specific_from: tuple[int, ...] = ()
    rpki: str = "any"
    # Aucune annonce attendue : le silence est l'état normal, toute annonce alerte.
    expect_silent: bool = False
    # Cibles ASN
    watch_prefix_set: bool = True
    watch_neighbours: bool = True
    ris_live_origin: bool = False

    @property
    def is_prefix(self) -> bool:
        return self.type == "prefix"

    @property
    def network(self) -> Network:
        return ipaddress.ip_network(self.resource)

    @property
    def asn(self) -> int:
        return int(self.resource)

    @property
    def more_specific_allowed(self) -> tuple[int, ...]:
        return self.allow_more_specific_from or self.expected_origins


@dataclass(frozen=True)
class Config:
    settings: Settings
    targets: tuple[Target, ...]
    path: str | None = None

    @property
    def prefix_targets(self) -> list[Target]:
        return [t for t in self.targets if t.is_prefix]

    @property
    def asn_targets(self) -> list[Target]:
        return [t for t in self.targets if not t.is_prefix]

    def target(self, label: str) -> Target | None:
        return next((t for t in self.targets if t.label == label), None)


# ── Lecture validée ───────────────────────────────────────────────────────

_MISSING: Any = object()


class _Section:
    """Lit un dictionnaire en accumulant les erreurs avec leur chemin."""

    def __init__(self, data: Any, path: str, errors: list[str]):
        self.path = path
        self.errors = errors
        self.seen: set[str] = set()
        if data is None:
            data = {}
        if not isinstance(data, dict):
            errors.append(f"{path} : un objet (clé: valeur) est attendu")
            data = {}
        self.data: dict[str, Any] = data

    def _err(self, key: str, msg: str) -> None:
        self.errors.append(f"{self.path}.{key} : {msg}")

    def get(
        self,
        key: str,
        kind: str,
        default: Any = _MISSING,
        *,
        choices: tuple[str, ...] | None = None,
        minimum: float | None = None,
        nullable: bool = False,
    ) -> Any:
        self.seen.add(key)
        if key not in self.data:
            if default is _MISSING:
                self._err(key, "champ obligatoire manquant")
                return None
            return default
        value = self.data[key]
        if value is None:
            if nullable:
                return None
            self._err(key, "valeur nulle non autorisée")
            return default if default is not _MISSING else None
        checker: dict[str, Callable[[Any], bool]] = {
            "str": lambda v: isinstance(v, str),
            "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "float": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "bool": lambda v: isinstance(v, bool),
            "dict": lambda v: isinstance(v, dict),
            "list": lambda v: isinstance(v, list),
        }
        if not checker[kind](value):
            self._err(key, f"type attendu {kind}, reçu {type(value).__name__}")
            return default if default is not _MISSING else None
        if choices is not None and value not in choices:
            self._err(key, f"valeur {value!r} non autorisée (choix : {', '.join(choices)})")
            return default if default is not _MISSING else None
        if minimum is not None and value < minimum:
            self._err(key, f"doit être >= {minimum}")
            return default if default is not _MISSING else None
        if kind == "float":
            return float(value)
        return value

    def asn_list(self, key: str) -> tuple[int, ...]:
        raw = self.get(key, "list", [])
        out: list[int] = []
        for i, item in enumerate(raw or []):
            try:
                out.append(parse_asn(item))
            except ValueError as exc:
                self._err(f"{key}[{i}]", str(exc))
        return tuple(dict.fromkeys(out))

    def finish(self) -> None:
        for key in self.data:
            if key not in self.seen:
                self._err(key, "clé inconnue")


def _parse_ripestat(data: Any, errors: list[str]) -> RipestatSettings:
    s = _Section(data, "settings.ripestat", errors)
    d = RipestatSettings()
    out = RipestatSettings(
        base_url=s.get("base_url", "str", d.base_url).rstrip("/"),
        sourceapp=s.get("sourceapp", "str", d.sourceapp),
        timeout=s.get("timeout", "float", d.timeout, minimum=1),
        retries=s.get("retries", "int", d.retries, minimum=0),
        backoff=s.get("backoff", "float", d.backoff, minimum=0),
        min_interval=s.get("min_interval", "float", d.min_interval, minimum=0),
        cache_ttl=s.get("cache_ttl", "int", d.cache_ttl, minimum=0),
        asn_prefix_window_hours=s.get(
            "asn_prefix_window_hours", "int", d.asn_prefix_window_hours, minimum=1
        ),
        max_more_specific_queries=s.get(
            "max_more_specific_queries", "int", d.max_more_specific_queries, minimum=0
        ),
        neighbour_types=_neighbour_types(s, d.neighbour_types, errors),
    )
    s.finish()
    return out


def _neighbour_types(s: _Section, default: tuple[str, ...], errors: list[str]) -> tuple[str, ...]:
    raw = s.get("neighbour_types", "list", list(default))
    allowed = ("left", "right", "uncertain")
    bad = [t for t in raw or [] if t not in allowed]
    if bad:
        errors.append(
            f"settings.ripestat.neighbour_types : valeurs inconnues {bad}"
            f" (choix : {', '.join(allowed)})"
        )
    return tuple(t for t in raw or [] if t in allowed) or default


def _parse_ris_live(data: Any, errors: list[str]) -> RisLiveSettings:
    s = _Section(data, "settings.ris_live", errors)
    d = RisLiveSettings()
    url = s.get("url", "str", d.url)
    if url and not url.startswith(("wss://", "ws://")):
        errors.append("settings.ris_live.url : une URL ws:// ou wss:// est attendue")
    out = RisLiveSettings(
        enabled=s.get("enabled", "bool", d.enabled),
        url=url,
        heartbeat_seconds=s.get("heartbeat_seconds", "int", d.heartbeat_seconds, minimum=5),
        reconnect_max_seconds=s.get(
            "reconnect_max_seconds", "int", d.reconnect_max_seconds, minimum=1
        ),
        queue_size=s.get("queue_size", "int", d.queue_size, minimum=100),
    )
    s.finish()
    return out


def _parse_irr(data: Any, errors: list[str]) -> IrrSettings:
    s = _Section(data, "settings.irr", errors)
    d = IrrSettings()
    servers: list[IrrServer] = []
    for i, raw in enumerate(s.get("servers", "list", [])):
        srv = _Section(raw, f"settings.irr.servers[{i}]", errors)
        servers.append(
            IrrServer(
                name=srv.get("name", "str"),
                host=srv.get("host", "str"),
                port=srv.get("port", "int", 43, minimum=1),
                query_prefix=srv.get("query_prefix", "str", ""),
            )
        )
        srv.finish()
    out = IrrSettings(
        enabled=s.get("enabled", "bool", d.enabled),
        interval=s.get("interval", "int", d.interval, minimum=60),
        timeout=s.get("timeout", "float", d.timeout, minimum=1),
        query_delay=s.get("query_delay", "float", d.query_delay, minimum=0),
        servers=tuple(servers),
    )
    s.finish()
    return out


def _parse_rpki(data: Any, errors: list[str]) -> RpkiSettings:
    s = _Section(data, "settings.rpki", errors)
    out = RpkiSettings(enabled=s.get("enabled", "bool", True))
    s.finish()
    return out


def _parse_report(data: Any, errors: list[str]) -> ReportSettings:
    s = _Section(data, "settings.report", errors)
    d = ReportSettings()
    out = ReportSettings(
        path=s.get("path", "str", d.path),
        refresh_seconds=s.get("refresh_seconds", "int", None, minimum=10, nullable=True),
        history_per_target=s.get("history_per_target", "int", d.history_per_target, minimum=1),
        timeline_size=s.get("timeline_size", "int", d.timeline_size, minimum=1),
    )
    s.finish()
    return out


def _parse_alerts(data: Any, errors: list[str]) -> AlertSettings:
    s = _Section(data, "settings.alerts", errors)
    cooldowns: dict[str, int] = {"default": 3600}
    for key, value in (s.get("cooldown_seconds", "dict", {}) or {}).items():
        if key != "default" and key not in EVENT_TYPES:
            errors.append(f"settings.alerts.cooldown_seconds.{key} : type d'événement inconnu")
        elif not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"settings.alerts.cooldown_seconds.{key} : entier >= 0 attendu")
        else:
            cooldowns[key] = value
    channels: list[AlertChannelConfig] = []
    for i, raw in enumerate(s.get("channels", "list", [])):
        c = _Section(raw, f"settings.alerts.channels[{i}]", errors)
        ctype = c.get("type", "str", choices=("console", "jsonl", "webhook"))
        ch = AlertChannelConfig(
            type=ctype,
            min_severity=c.get("min_severity", "str", "info", choices=SEVERITIES),
            path=c.get("path", "str", None, nullable=True),
            url=c.get("url", "str", None, nullable=True),
            url_env=c.get("url_env", "str", None, nullable=True),
            format=c.get("format", "str", "auto", choices=WEBHOOK_FORMATS),
            timeout=c.get("timeout", "float", 10.0, minimum=1),
        )
        c.finish()
        if ctype == "jsonl" and not ch.path:
            errors.append(f"settings.alerts.channels[{i}] : 'path' obligatoire pour jsonl")
        if ctype == "webhook" and not (ch.url or ch.url_env):
            errors.append(f"settings.alerts.channels[{i}] : 'url_env' (ou 'url') obligatoire")
        channels.append(ch)
    out = AlertSettings(cooldown_seconds=cooldowns, channels=tuple(channels))
    s.finish()
    return out


def _parse_settings(data: Any, errors: list[str]) -> Settings:
    s = _Section(data, "settings", errors)
    d = Settings()
    overrides: dict[str, str] = {}
    for key, value in (s.get("severity_overrides", "dict", {}) or {}).items():
        if key not in EVENT_TYPES:
            errors.append(f"settings.severity_overrides.{key} : type d'événement inconnu")
        elif value not in SEVERITIES:
            errors.append(f"settings.severity_overrides.{key} : sévérité inconnue {value!r}")
        else:
            overrides[key] = value
    out = Settings(
        check_interval=s.get("check_interval", "int", d.check_interval, minimum=30),
        log_level=s.get("log_level", "str", d.log_level, choices=LOG_LEVELS),
        log_format=s.get("log_format", "str", d.log_format, choices=("text", "json")),
        log_file=s.get("log_file", "str", d.log_file, nullable=True),
        db_path=s.get("db_path", "str", d.db_path),
        recent_window_hours=s.get("recent_window_hours", "int", d.recent_window_hours, minimum=1),
        source_error_cycles=s.get("source_error_cycles", "int", d.source_error_cycles, minimum=1),
        visibility_drop_pct=s.get("visibility_drop_pct", "float", d.visibility_drop_pct, minimum=1),
        severity_overrides=overrides,
        ripestat=_parse_ripestat(s.get("ripestat", "dict", {}), errors),
        ris_live=_parse_ris_live(s.get("ris_live", "dict", {}), errors),
        rpki=_parse_rpki(s.get("rpki", "dict", {}), errors),
        irr=_parse_irr(s.get("irr", "dict", {}), errors),
        report=_parse_report(s.get("report", "dict", {}), errors),
        alerts=_parse_alerts(s.get("alerts", "dict", {}), errors),
    )
    s.finish()
    return out


_PREFIX_ONLY = (
    "expected_origins",
    "forbidden_origins",
    "forbidden_path_asns",
    "expected_upstreams",
    "max_prefix_length",
    "allow_more_specific_from",
    "rpki",
    "expect_silent",
)
_ASN_ONLY = ("watch_prefix_set", "watch_neighbours", "ris_live_origin")


def _parse_target(raw: Any, index: int, errors: list[str]) -> Target | None:
    path = f"targets[{index}]"
    s = _Section(raw, path, errors)
    label = s.get("label", "str")
    if label:
        path = f"targets[{index}] ({label})"
        s.path = path
    ttype = s.get("type", "str", choices=("prefix", "asn"))
    s.seen.add("resource")
    raw_resource = s.data.get("resource")
    if raw_resource is None:
        errors.append(f"{path}.resource : champ obligatoire manquant")
    common = {
        "role": s.get("role", "str", ""),
        "description": s.get("description", "str", ""),
        "severity": s.get("severity", "str", "high", choices=SEVERITIES),
        "irr": s.get("irr", "str", "ignore", choices=("watch", "ignore")),
    }
    if ttype is None or raw_resource is None or label is None:
        s.finish()
        return None

    if ttype == "prefix":
        for key in _ASN_ONLY:
            if key in s.data:
                s.seen.add(key)
                errors.append(f"{path}.{key} : réservé aux cibles de type asn")
        try:
            network = ipaddress.ip_network(str(raw_resource).strip(), strict=True)
        except ValueError as exc:
            errors.append(f"{path}.resource : préfixe invalide ({exc})")
            s.finish()
            return None
        max_len = s.get("max_prefix_length", "int", None, nullable=True)
        if max_len is not None and not network.prefixlen <= max_len <= network.max_prefixlen:
            errors.append(
                f"{path}.max_prefix_length : doit être entre /{network.prefixlen} "
                f"et /{network.max_prefixlen}"
            )
        target = Target(
            label=label,
            type="prefix",
            resource=str(network),
            expected_origins=s.asn_list("expected_origins"),
            forbidden_origins=s.asn_list("forbidden_origins"),
            forbidden_path_asns=s.asn_list("forbidden_path_asns"),
            expected_upstreams=s.asn_list("expected_upstreams"),
            max_prefix_length=max_len,
            allow_more_specific_from=s.asn_list("allow_more_specific_from"),
            rpki=s.get("rpki", "str", "any", choices=("expect_valid", "any")),
            expect_silent=s.get("expect_silent", "bool", False),
            **common,
        )
        if target.expect_silent and (target.expected_origins or target.allow_more_specific_from):
            errors.append(
                f"{path} : expect_silent est incompatible avec expected_origins"
                " et allow_more_specific_from"
            )
        overlap = set(target.expected_origins) & set(target.forbidden_origins)
        if overlap:
            errors.append(f"{path} : ASN à la fois attendu et interdit : {sorted(overlap)}")
    else:
        for key in _PREFIX_ONLY:
            if key in s.data:
                s.seen.add(key)
                errors.append(f"{path}.{key} : réservé aux cibles de type prefix")
        try:
            asn = parse_asn(raw_resource)
        except ValueError as exc:
            errors.append(f"{path}.resource : {exc}")
            s.finish()
            return None
        target = Target(
            label=label,
            type="asn",
            resource=str(asn),
            watch_prefix_set=s.get("watch_prefix_set", "bool", True),
            watch_neighbours=s.get("watch_neighbours", "bool", True),
            ris_live_origin=s.get("ris_live_origin", "bool", False),
            **common,
        )
    s.finish()
    return target


def parse_config(data: Any, path: str | None = None) -> Config:
    errors: list[str] = []
    root = _Section(data, "config", errors)
    version = root.get("version", "int")
    if version is not None and version != CONFIG_VERSION:
        errors.append(
            f"config.version : version {version} non prise en charge (attendu {CONFIG_VERSION}) ;"
            " utilisez `python -m bgpmon migrate-config` pour l'ancien format"
        )
    settings = _parse_settings(root.get("settings", "dict", {}), errors)
    raw_targets = root.get("targets", "list") or []
    if not raw_targets:
        errors.append("config.targets : au moins une cible est requise")
    targets: list[Target] = []
    for i, raw in enumerate(raw_targets):
        t = _parse_target(raw, i, errors)
        if t is not None:
            targets.append(t)
    labels = [t.label for t in targets]
    for dup in sorted({lbl for lbl in labels if labels.count(lbl) > 1}):
        errors.append(f"config.targets : label en double {dup!r}")
    if GLOBAL_TARGET in labels:
        errors.append(f"config.targets : le label {GLOBAL_TARGET!r} est réservé")
    root.finish()
    if errors:
        raise ConfigError(errors)
    return Config(settings=settings, targets=tuple(targets), path=path)


def read_file(path: str | Path) -> Any:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError([f"fichier introuvable : {p}"]) from exc
    try:
        if p.suffix.lower() == ".json":
            return json.loads(text)
        return yaml.safe_load(text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ConfigError([f"{p} : syntaxe invalide ({exc})"]) from exc


def load_config(path: str | Path) -> Config:
    return parse_config(read_file(path), str(path))


# ── Migration depuis la v2.4 ──────────────────────────────────────────────


def extract_legacy_default_config(source: str) -> dict[str, Any]:
    """Extrait `DEFAULT_CONFIG` d'un script v2.4 sans l'exécuter (analyse AST)."""
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "DEFAULT_CONFIG" for t in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, dict):
                return value
    raise ConfigError(["DEFAULT_CONFIG introuvable dans le script fourni"])


def load_legacy(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError([f"fichier introuvable : {p}"]) from exc
    if p.suffix == ".py":
        return extract_legacy_default_config(text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError([f"{p} : JSON invalide ({exc})"]) from exc
    if not isinstance(data, dict):
        raise ConfigError([f"{p} : objet JSON attendu"])
    return data


def _legacy_asn(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return parse_asn(value)


def migrate_legacy(legacy: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Convertit une configuration v2.4 en configuration v3 (dictionnaire) + avertissements."""
    warnings: list[str] = [
        "Relisez les champs role/description : aucun nom de personne physique ne doit y figurer.",
    ]
    if legacy.get("webhook_url"):
        warnings.append(
            "webhook_url présent dans l'ancienne config : il n'est PAS recopié. "
            "Exportez-le dans la variable d'environnement BGPMON_WEBHOOK_URL."
        )
    targets: list[dict[str, Any]] = []
    for raw in legacy.get("targets", []):
        ttype = raw.get("type")
        legit = _legacy_asn(raw.get("legit_asn"))
        hijack = _legacy_asn(raw.get("hijack_asn"))
        base: dict[str, Any] = {
            "label": raw.get("label") or str(raw.get("resource")),
            "type": ttype,
            "resource": raw.get("resource"),
            "role": raw.get("role", ""),
            "description": raw.get("desc", ""),
        }
        if ttype == "prefix":
            net = ipaddress.ip_network(str(raw["resource"]), strict=False)
            expected = [legit] if legit is not None else []
            base.update(
                {
                    "expected_origins": expected,
                    "forbidden_origins": [hijack] if hijack is not None else [],
                    "forbidden_path_asns": [hijack] if hijack is not None else [],
                    "expected_upstreams": [],
                    "max_prefix_length": 24 if net.version == 4 and net.prefixlen <= 24 else None,
                    "allow_more_specific_from": expected,
                    "rpki": "any",
                    "irr": "watch",
                    "severity": "critical"
                    if legit is not None
                    else ("high" if hijack is not None else "warning"),
                }
            )
            if net.version == 6 and net.prefixlen <= 48:
                base["max_prefix_length"] = 48
        elif ttype == "asn":
            base["resource"] = parse_asn(raw.get("resource"))
            base.update(
                {
                    "watch_prefix_set": True,
                    "watch_neighbours": True,
                    "ris_live_origin": False,
                    "irr": "ignore",
                    "severity": "high",
                }
            )
            if raw.get("legit_asn") or raw.get("hijack_asn"):
                warnings.append(
                    f"{base['label']} : legit_asn/hijack_asn ignorés pour une cible ASN."
                )
        else:
            warnings.append(f"Cible ignorée (type inconnu {ttype!r}) : {raw!r}")
            continue
        targets.append(base)
    settings: dict[str, Any] = {"check_interval": int(legacy.get("refresh_seconds", 300))}
    return {"version": CONFIG_VERSION, "settings": settings, "targets": targets}, warnings


def dump_yaml(data: dict[str, Any], header: str = "") -> str:
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
    prefix = "".join(f"# {line}\n" if line else "#\n" for line in header.splitlines())
    return prefix + body
