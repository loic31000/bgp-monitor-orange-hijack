"""Interface en ligne de commande : `python -m bgpmon <commande>`."""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from bgpmon import __version__
from bgpmon.alerts import AlertDispatcher, build_channels
from bgpmon.config import (
    Config,
    ConfigError,
    dump_yaml,
    load_config,
    load_legacy,
    migrate_legacy,
    parse_config,
)
from bgpmon.models import EVENT_TYPES, SEVERITIES, SEVERITY_RANK, Event, iso, make_key
from bgpmon.monitor import Monitor
from bgpmon.report import (
    build_report_data,
    events_to_csv,
    events_to_json,
    events_to_table,
    render_summary,
    write_report,
    write_text_atomic,
)
from bgpmon.sources.irr import IrrClient
from bgpmon.sources.ripestat import RipeStatClient
from bgpmon.sources.ris_live import RisLiveClient, build_subscriptions
from bgpmon.state import State

log = logging.getLogger("bgpmon")

EXIT_OK, EXIT_ERROR, EXIT_ALERT, EXIT_UNKNOWN = 0, 1, 2, 3
# Durée maximale de vidage de la file à l'arrêt (inférieure au TimeoutStopSec de systemd).
DRAIN_SECONDS = 20


def out(text: str) -> None:
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    sys.stdout.flush()


# ── Logging ───────────────────────────────────────────────────────────────


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str, fmt: str = "text", log_file: str | None = None) -> None:
    formatter: logging.Formatter = (
        JsonFormatter()
        if fmt == "json"
        else logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s : %(message)s", "%Y-%m-%d %H:%M:%S"
        )
    )
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    root.addHandler(console)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(formatter)
        root.addHandler(fh)
    root.setLevel(level)
    for noisy in ("urllib3", "websocket"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, root.level))


# ── Construction ──────────────────────────────────────────────────────────


def _load(args: argparse.Namespace) -> Config:
    config = load_config(args.config)
    s = config.settings
    if args.command in ("once", "run"):
        setup_logging(args.log_level or s.log_level, s.log_format, s.log_file)
    elif args.log_level:
        setup_logging(args.log_level, s.log_format)
    return config


def build_monitor(config: Config) -> tuple[Monitor, State, RipeStatClient]:
    s = config.settings
    state = State(s.db_path)
    ripestat = RipeStatClient(s.ripestat)
    irr = IrrClient(s.irr) if s.irr.enabled and s.irr.servers else None
    dispatcher = AlertDispatcher(build_channels(s.alerts), s.alerts, state)
    return Monitor(config, state, ripestat, irr, dispatcher), state, ripestat


def _exit_code(states: dict[str, str], allow_unknown: bool) -> int:
    if "ALERT" in states.values():
        return EXIT_ALERT
    if "UNKNOWN" in states.values() and not allow_unknown:
        return EXIT_UNKNOWN
    return EXIT_OK


# ── Commandes ─────────────────────────────────────────────────────────────


def cmd_test_alert(args: argparse.Namespace) -> int:
    """Envoie une alerte factice sur les canaux configurés, sans cooldown ni base."""
    config = _load(args)
    channels = [
        c
        for c in build_channels(config.settings.alerts)
        if not args.channel or c.name == args.channel
    ]
    if not channels:
        sys.stderr.write(
            "Aucun canal actif"
            + (f" de type {args.channel}" if args.channel else "")
            + " : vérifiez settings.alerts.channels et la variable BGPMON_WEBHOOK_URL.\n"
        )
        return EXIT_ERROR
    event = Event(
        type="TEST_ALERT",
        severity=args.severity,
        target="test",
        source="bgpmon test-alert",
        key=make_key("TEST_ALERT", "test", iso()),
        message="Alerte de test envoyée par `bgpmon test-alert` — aucune action requise",
        stateful=False,
        phase="oneshot",
        prefix="192.0.2.0/24",
        origin=64496,
        as_path=[64511, 64496],
        evidence={"test": True},
    )
    failed = 0
    for channel in channels:
        if SEVERITY_RANK[event.severity] < SEVERITY_RANK[channel.min_severity]:
            out(f"  {channel.name} : ignoré (min_severity {channel.min_severity})")
            continue
        try:
            channel.send(event)
            out(f"  {channel.name} : envoyé")
        except Exception as exc:  # noqa: BLE001 — on rapporte l'échec de chaque canal
            failed += 1
            out(f"  {channel.name} : ÉCHEC ({exc})")
    return EXIT_ERROR if failed else EXIT_OK


def cmd_check_config(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    s = config.settings
    out(f"Configuration valide : {args.config}")
    out(f"  {len(config.prefix_targets)} préfixe(s), {len(config.asn_targets)} ASN")
    out(f"  Intervalle : {s.check_interval} s, rafraîchissement du rapport : {s.report_refresh} s")
    out(
        f"  RIS Live : {'activé' if s.ris_live.enabled else 'désactivé'}, "
        f"{len(build_subscriptions(config))} abonnement(s)"
    )
    out(
        f"  RPKI : {'activé' if s.rpki.enabled else 'désactivé'} ; IRR : "
        f"{'activé' if s.irr.enabled else 'désactivé'} ({', '.join(x.name for x in s.irr.servers)})"
    )
    for ch in s.alerts.channels:
        if ch.type == "webhook":
            ready = bool(os.environ.get(ch.url_env or "")) or bool(ch.url)
            out(
                f"  Canal webhook ({ch.format}) : "
                f"{'URL présente' if ready else f'variable {ch.url_env} absente, canal inactif'}"
            )
        else:
            out(f"  Canal {ch.type}{f' : {ch.path}' if ch.path else ''}")
    for t in config.targets:
        out(f"  - {t.label:<20} {t.type:<6} {t.severity:<8} {t.role}")
    return EXIT_OK


def cmd_migrate_config(args: argparse.Namespace) -> int:
    legacy = load_legacy(args.input)
    data, warnings = migrate_legacy(legacy)
    parse_config(data)  # le résultat doit être valide avant d'être écrit
    text = dump_yaml(
        data,
        header=(
            f"Configuration bgpmon v3 migrée depuis {Path(args.input).name}.\n"
            "Complétez expected_upstreams, rpki et les réglages (voir config.example.yaml)."
        ),
    )
    for w in warnings:
        sys.stderr.write(f"Attention : {w}\n")
    if not args.output:
        out(text)
        return EXIT_OK
    target = Path(args.output)
    if target.exists() and not args.force:
        sys.stderr.write(f"{target} existe déjà : utilisez --force pour l'écraser.\n")
        return EXIT_ERROR
    write_text_atomic(target, text)
    sys.stderr.write(f"Configuration écrite dans {target} ({len(data['targets'])} cibles).\n")
    return EXIT_OK


def cmd_once(args: argparse.Namespace) -> int:
    config = _load(args)
    monitor, state, ripestat = build_monitor(config)
    try:
        include_irr = config.settings.irr.enabled and not args.no_irr
        events = monitor.run_cycle(include_irr=include_irr)
        states = monitor.refresh_all()
        path = write_report(config, state)
        out(render_summary(build_report_data(config, state)))
        out(f"\n{len(events)} transition(s) enregistrée(s). Rapport : {path}")
        return _exit_code(states, args.allow_unknown)
    finally:
        ripestat.close()
        state.close()


def cmd_run(args: argparse.Namespace) -> int:
    config = _load(args)
    s = config.settings
    monitor, state, ripestat = build_monitor(config)
    stop = threading.Event()
    items: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=s.ris_live.queue_size)
    dropped = 0

    def on_signal(signum: int, _frame: Any) -> None:
        log.info("Signal %s reçu : arrêt propre en cours", signum)
        stop.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    def put_live(item: tuple[str, Any]) -> None:
        nonlocal dropped
        try:
            items.put_nowait(item)
        except queue.Full:
            dropped += 1
            if dropped % 1000 == 1:
                log.warning("File pleine : %d message(s) RIS Live ignoré(s)", dropped)

    def put_blocking(item: tuple[str, Any]) -> bool:
        while not stop.is_set():
            try:
                items.put(item, timeout=1)
                return True
            except queue.Full:
                continue
        return False

    def checker() -> None:
        next_irr = 0.0
        while not stop.is_set():
            started = time.monotonic()
            for target in config.targets:
                if stop.is_set() or not put_blocking(("obs", monitor.collect(target))):
                    return
            if monitor.irr is not None and not args.no_irr and time.monotonic() >= next_irr:
                for target in config.targets:
                    if stop.is_set():
                        return
                    irr_obs = monitor.collect_irr(target)
                    if irr_obs is not None and not put_blocking(("obs", irr_obs)):
                        return
                next_irr = time.monotonic() + s.irr.interval
            put_blocking(("cycle", time.monotonic() - started))
            stop.wait(max(0.0, s.check_interval - (time.monotonic() - started)))

    threads = [threading.Thread(target=checker, name="checker", daemon=True)]
    live_client: RisLiveClient | None = None
    if s.ris_live.enabled and not args.no_live:
        live_client = RisLiveClient(
            s.ris_live,
            build_subscriptions(config),
            on_update=lambda upd: put_live(("live", upd)),
            on_status=lambda st, detail: put_live(("live_status", (st, detail))),
        )
        threads.append(
            threading.Thread(target=live_client.run, args=(stop,), name="ris-live", daemon=True)
        )
    log.info(
        "bgpmon v%s démarré : %d cible(s), RIS Live %s",
        __version__,
        len(config.targets),
        "activé" if live_client else "désactivé",
    )
    for th in threads:
        th.start()

    deadline = time.monotonic() + args.duration if args.duration else None
    last_report = last_stats = time.monotonic()
    live_seen = live_events = 0
    dirty = False

    def handle(kind: str, payload: Any) -> None:
        nonlocal dirty, live_seen, live_events
        if kind == "obs":
            monitor.process(payload)
            dirty = True
        elif kind == "live":
            live_seen += 1
            if monitor.handle_live_update(payload):
                live_events += 1
                dirty = True
        elif kind == "live_status":
            monitor.handle_live_status(*payload)
        elif kind == "cycle":
            monitor.refresh_all()
            write_report(config, state)
            dirty = False
            log.info("Passage terminé en %.0f s ; rapport mis à jour", payload)

    try:
        while not stop.is_set():
            if deadline is not None and time.monotonic() >= deadline:
                log.info("Durée demandée atteinte (%s s)", args.duration)
                stop.set()
                break
            try:
                kind, payload = items.get(timeout=1)
            except queue.Empty:
                kind, payload = "", None
            if kind:
                handle(kind, payload)
            now = time.monotonic()
            if dirty and now - last_report >= 30:
                write_report(config, state)
                last_report, dirty = now, False
            if now - last_stats >= 60:
                log.info(
                    "RIS Live : %d mise(s) à jour reçue(s), %d avec transition",
                    live_seen,
                    live_events,
                )
                last_stats = now
    finally:
        stop.set()
        for th in threads:
            th.join(timeout=10)
        # Les éléments déjà collectés sont traités avant la fermeture de la base, dans
        # la limite de DRAIN_SECONDS : les observations passent avant les messages RIS Live.
        pending: list[tuple[str, Any]] = []
        while True:
            try:
                pending.append(items.get_nowait())
            except queue.Empty:
                break
        pending.sort(key=lambda item: item[0] == "live")
        drain_deadline = time.monotonic() + DRAIN_SECONDS
        skipped = 0
        for kind, payload in pending:
            if kind == "live" and time.monotonic() > drain_deadline:
                skipped += 1
                continue
            handle(kind, payload)
        if skipped:
            log.warning(
                "Arrêt : %d message(s) RIS Live en file non traités (délai dépassé)", skipped
            )
        monitor.refresh_all()
        write_report(config, state)
        log.info(
            "Arrêt : %d mise(s) à jour RIS Live traitée(s), %d ignorée(s)",
            live_seen,
            dropped + skipped,
        )
        ripestat.close()
        state.close()
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    config = _load(args)
    state = State(config.settings.db_path)
    try:
        path = write_report(config, state, args.output)
        out(f"Rapport écrit : {path}")
        if args.csv or args.json:
            events = state.query_events(limit=None)
            if args.csv:
                write_text_atomic(args.csv, events_to_csv(events))
                out(f"Export CSV : {args.csv} ({len(events)} événements)")
            if args.json:
                write_text_atomic(args.json, events_to_json(events))
                out(f"Export JSON : {args.json} ({len(events)} événements)")
    finally:
        state.close()
    return EXIT_OK


def cmd_events(args: argparse.Namespace) -> int:
    config = _load(args)
    state = State(config.settings.db_path)
    try:
        events = state.query_events(
            target=args.target,
            types=args.type,
            min_severity=args.severity,
            since=args.since,
            phase=args.phase,
            limit=args.limit or None,
        )
    finally:
        state.close()
    render = {"table": events_to_table, "csv": events_to_csv, "json": events_to_json}
    text = render[args.format](events)
    if args.output:
        write_text_atomic(args.output, text)
        out(f"{len(events)} événement(s) écrit(s) dans {args.output}")
    else:
        out(text)
    return EXIT_OK


# ── Analyseur d'arguments ─────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bgpmon",
        description="Moniteur BGP passif : RIS Live, RIPEstat, RPKI et IRR.",
    )
    parser.add_argument("--version", action="version", version=f"bgpmon {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-c",
        "--config",
        default=os.environ.get("BGPMON_CONFIG", "config.yaml"),
        help="fichier de configuration YAML ou JSON (défaut : $BGPMON_CONFIG ou config.yaml)",
    )
    common.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="surcharge settings.log_level",
    )
    sub = parser.add_subparsers(dest="command", metavar="commande")

    p = sub.add_parser("run", parents=[common], help="surveillance continue (RIS Live + passages)")
    p.add_argument("--duration", type=int, help="s'arrêter après N secondes (test)")
    p.add_argument("--no-live", action="store_true", help="désactiver RIS Live")
    p.add_argument("--no-irr", action="store_true", help="désactiver les requêtes IRR")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser(
        "once", parents=[common], help="un passage ; code 2 si alerte, 3 si état inconnu"
    )
    p.add_argument("--no-irr", action="store_true", help="désactiver les requêtes IRR")
    p.add_argument(
        "--allow-unknown",
        action="store_true",
        help="ne pas échouer (code 3) sur une cible en état inconnu",
    )
    p.set_defaults(func=cmd_once)

    p = sub.add_parser("report", parents=[common], help="régénérer le rapport HTML")
    p.add_argument("-o", "--output", help="chemin du rapport (défaut : settings.report.path)")
    p.add_argument("--csv", help="exporter aussi tous les événements en CSV")
    p.add_argument("--json", help="exporter aussi tous les événements en JSON")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("events", parents=[common], help="lister les événements")
    p.add_argument("--target", help="label de cible")
    p.add_argument("--type", action="append", choices=EVENT_TYPES, help="type (répétable)")
    p.add_argument("--severity", choices=SEVERITIES, help="sévérité minimale")
    p.add_argument("--since", help="horodatage ISO minimal, ex. 2026-10-01")
    p.add_argument("--phase", choices=("raised", "resolved", "oneshot"))
    p.add_argument("--limit", type=int, default=50, help="0 = sans limite (défaut 50)")
    p.add_argument("--format", choices=("table", "csv", "json"), default="table")
    p.add_argument("-o", "--output", help="écrire dans un fichier")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("migrate-config", help="convertir une configuration v2.4 en v3")
    p.add_argument(
        "input",
        nargs="?",
        default="config.json",
        help="ancien config.json ou script bgp_monitor.py v2.4 (DEFAULT_CONFIG)",
    )
    p.add_argument("-o", "--output", help="fichier YAML de sortie (défaut : sortie standard)")
    p.add_argument("--force", action="store_true", help="écraser le fichier de sortie")
    p.set_defaults(func=cmd_migrate_config)

    p = sub.add_parser("check-config", parents=[common], help="valider la configuration")
    p.set_defaults(func=cmd_check_config)

    p = sub.add_parser(
        "test-alert", parents=[common], help="envoyer une alerte factice sur les canaux configurés"
    )
    p.add_argument(
        "--channel", choices=("console", "jsonl", "webhook"), help="limiter à un type de canal"
    )
    p.add_argument(
        "--severity",
        choices=SEVERITIES,
        default="critical",
        help="sévérité de l'alerte factice (défaut : critical)",
    )
    p.set_defaults(func=cmd_test_alert)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Console Windows : forcer l'UTF-8 pour les accents et les flèches.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_ERROR
    if not logging.getLogger().handlers:
        setup_logging(getattr(args, "log_level", None) or "WARNING")
    try:
        code: int = args.func(args)
        return code
    except ConfigError as exc:
        sys.stderr.write(f"{exc}\n")
        if (
            not Path(getattr(args, "config", "") or ".").exists()
            and getattr(args, "command", "") != "migrate-config"
        ):
            sys.stderr.write("Astuce : cp config.example.yaml config.yaml\n")
        return EXIT_ERROR
