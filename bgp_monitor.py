#!/usr/bin/env python3
# bgp_monitor.py — Version 2.1 — Corrections complètes
import requests
import time
import os
import json
import argparse
from datetime import datetime, timezone
 
# ── Couleurs ANSI ──────────────────────────────────────────────
R      = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GRN    = "\033[92m"
YLW    = "\033[93m"
BLU    = "\033[94m"
MGT    = "\033[95m"
CYN    = "\033[96m"
WHT    = "\033[97m"
BG_RED  = "\033[41m"
BG_GRN  = "\033[42m"
BG_YLW  = "\033[43m"
BG_BLU  = "\033[44m"
BG_DARK = "\033[100m"
 
 
def clr(text, *codes):
    return "".join(codes) + str(text) + R
 
 
def badge_ok(t):   return clr(f" {t} ", BG_GRN, BOLD, WHT)
def badge_ko(t):   return clr(f" {t} ", BG_RED, BOLD, WHT)
def badge_warn(t): return clr(f" {t} ", BG_YLW, BOLD, WHT)
def badge_info(t): return clr(f" {t} ", BG_BLU, BOLD, WHT)
def badge_dim(t):  return clr(f" {t} ", BG_DARK, WHT)
 
 
def sep(char="─", n=70, color=CYN):
    print(clr(char * n, color))
 
 
def h1(text):
    sep("═")
    print(clr(f"  {text}", BOLD, CYN))
    sep("═")
 
 
def h2(text):
    sep()
    print(clr(f"  {text}", BOLD, WHT))
    sep()
 
 
# ── Chargement de la configuration ────────────────────────────
DEFAULT_CONFIG = {
    "refresh_seconds": 300,
    "webhook_url": None,
    "targets": [
        {
            "label": "90.98.0.0/15",
            "type": "prefix",
            "resource": "90.98.0.0/15",
            "role": "Préfixe hijacké",
            "legit_asn": "3215",
            "hijack_asn": "41128",
            "desc": "Orange France — Espace IP légitime"
        },
        {
            "label": "92.183.128.0/18",
            "type": "prefix",
            "resource": "92.183.128.0/18",
            "role": "Cible secondaire",
            "legit_asn": "3215",
            "hijack_asn": "263692",
            "desc": "Orange France — Pré-positionnement"
        },
        {
            "label": "AS41128",
            "type": "asn",
            "resource": "41128",
            "role": "Origine frauduleuse",
            "legit_asn": None,
            "hijack_asn": "41128",
            "desc": "ORANGEFR-GRX-AS — ASN compromis"
        },
        {
            "label": "AS3215",
            "type": "asn",
            "resource": "3215",
            "role": "Orange légitime",
            "legit_asn": "3215",
            "hijack_asn": None,
            "desc": "Orange France — Propriétaire réel"
        },
        {
            "label": "AS29802",
            "type": "asn",
            "resource": "29802",
            "role": "Destination finale",
            "legit_asn": None,
            "hijack_asn": None,
            "desc": "Hivelocity Dallas TX — Infra réelle"
        },
    ]
}
 
CONFIG_FILE = "config.json"
 
 
def load_config():
    """Charge config.json si présent, sinon retourne la config par défaut."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        # Fusion : les clés user écrasent les défauts
        cfg = {**DEFAULT_CONFIG, **user_cfg}
        print(clr(f"  Config chargée depuis {CONFIG_FILE}", DIM, GRN))
    else:
        cfg = DEFAULT_CONFIG.copy()
        # Génère un config.json d'exemple au premier lancement
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        print(clr(f"  config.json généré — modifiez-le pour personnaliser les cibles.", DIM, YLW))
    return cfg
 
 
# ── API RIPEstat ───────────────────────────────────────────────
def fetch_prefix(prefix):
    """Interroge RIPEstat pour un préfixe et retourne origines + visibilité."""
    try:
        url = (
            "https://stat.ripe.net/data/routing-status/data.json"
            f"?resource={prefix}"
        )
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        d = r.json().get("data", {})
        origins = [str(o.get("origin", "")) for o in d.get("origins", [])]
        peers   = d.get("visibility", {})
        total   = peers.get("total_ris_peers", 0)
        visible = peers.get("ris_peers_seeing", 0)
        return {
            "origins":     origins,
            "visible":     visible,
            "total":       total,
            "last_update": d.get("last_update", "—"),
        }
    except requests.RequestException as e:
        return {"error": str(e)}
 
 
def fetch_asn(asn):
    """Interroge RIPEstat pour un ASN et retourne le nombre de préfixes annoncés."""
    try:
        url = (
            "https://stat.ripe.net/data/announced-prefixes/data.json"
            f"?resource=AS{asn}"
        )
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        d        = r.json().get("data", {})
        prefixes = d.get("prefixes", [])
        return {"prefix_count": len(prefixes), "asn": asn}
    except requests.RequestException as e:
        return {"error": str(e)}
 
 
# ── Analyse d'une cible ────────────────────────────────────────
def analyse(target):
    """Analyse une cible et retourne un dict de résultat normalisé."""
    result = {
        "label": target["label"],
        "role":  target["role"],
        "desc":  target["desc"],
        "ts":    datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
    }
 
    if target["type"] == "prefix":
        data = fetch_prefix(target["resource"])
        if "error" in data:
            result.update({"status": "ERROR", "detail": data["error"]})
            return result
 
        origins    = data["origins"]
        visible    = data["visible"]
        total      = data["total"]
        pct        = round(visible / total * 100, 1) if total else 0
        hijack_asn = target.get("hijack_asn")
 
        # FIX : condition unique et correcte — l'ASN frauduleux est-il présent ?
        if hijack_asn and hijack_asn in origins:
            status = "HIJACK"
        else:
            status = "CLEAN"
 
        result.update({
            "status":      status,
            "origins":     origins,
            "visible":     visible,
            "total":       total,
            "pct":         pct,
            "last_update": data["last_update"],
        })
 
    else:  # type == "asn"
        data = fetch_asn(target["resource"])
        if "error" in data:
            result.update({"status": "ERROR", "detail": data["error"]})
            return result
        count = data["prefix_count"]
        result.update({
            "status":       "ACTIVE" if count > 0 else "SILENT",
            "prefix_count": count,
        })
 
    return result
 
 
# ── Alertes webhook (Discord / Slack / générique) ──────────────
def send_webhook(webhook_url, message):
    """Envoie une alerte JSON vers un webhook Discord/Slack."""
    if not webhook_url:
        return
    try:
        payload = {"content": message}          # Discord
        # Pour Slack, remplacer par : {"text": message}
        requests.post(webhook_url, json=payload, timeout=5)
    except requests.RequestException:
        pass  # L'alerte webhook ne doit jamais planter le monitoring
 
 
# ── Affichage terminal ─────────────────────────────────────────
def print_result(res, idx):
    label  = res["label"]
    status = res["status"]
    role   = res["role"]
    desc   = res["desc"]
 
    badges = {
        "HIJACK": badge_ko("⚠  HIJACK DÉTECTÉ"),
        "CLEAN":  badge_ok("✔  CLEAN"),
        "ACTIVE": badge_ok("✔  ACTIF"),
        "SILENT": badge_warn("~  SILENCIEUX"),
    }
    b = badges.get(status, badge_dim("?  ERREUR"))
 
    print(
        f"  {clr(f'[{idx}]', DIM, CYN)}  "
        f"{clr(label, BOLD, WHT)}  "
        f"{clr(f'({role})', DIM)}  {b}"
    )
    print(f"       {clr(desc, DIM)}")
 
    if "origins" in res:
        orig_str  = ", ".join(res["origins"]) if res["origins"] else "aucune"
        color     = RED if status == "HIJACK" else GRN
        vis_color = RED if (res["pct"] > 50 and status == "HIJACK") else GRN
        print(f"       Origines   : {clr(orig_str, color, BOLD)}")
        vis_str = str(res["visible"]) + "/" + str(res["total"]) + " peers"
        pct_str = "(" + str(res["pct"]) + "%)"
        print(
            f"       Visibilité : {clr(vis_str, vis_color)} "
            f"{clr(pct_str, BOLD, vis_color)}"
        )
        print(f"       Dernière MAJ : {clr(res.get('last_update', '—'), DIM)}")
 
    if "prefix_count" in res:
        c   = res["prefix_count"]
        col = GRN if c > 0 else YLW
        print(f"       Préfixes annoncés : {clr(c, col, BOLD)}")
 
    if "detail" in res:
        print(f"       {clr('Erreur: ' + res['detail'], RED)}")
 
    print()
 
 
# ── Rapport HTML ───────────────────────────────────────────────
STATUS_COLORS = {
    "HIJACK": ("#ff4444", "#2a0000"),
    "CLEAN":  ("#00cc66", "#001a0d"),
    "ACTIVE": ("#00cc66", "#001a0d"),
    "SILENT": ("#ffaa00", "#1a1000"),
    "ERROR":  ("#888888", "#111111"),
}
 
 
def clr_html(sym, color):
    return f'<span style="color:{color}">{sym}</span>'
 
 
def generate_html(results, check_num, timestamp, history):
    rows = ""
    alerts = [r for r in results if r["status"] == "HIJACK"]
 
    for res in results:
        status = res["status"]
        fg, bg = STATUS_COLORS.get(status, ("#aaa", "#111"))
        badge = (
            f'<span style="background:{fg};color:#000;padding:3px 10px;'
            f'border-radius:4px;font-weight:bold;font-size:0.85em">{status}</span>'
        )
 
        details = ""
        if "origins" in res:
            orig    = ", ".join(res["origins"]) or "aucune"
            details = (
                f'<br><small>Origines: <b>{orig}</b> | '
                f'Visibilité: {res["visible"]}/{res["total"]} ({res["pct"]}%)</small>'
            )
        if "prefix_count" in res:
            details = f'<br><small>Préfixes annoncés: <b>{res["prefix_count"]}</b></small>'
 
        hist  = history.get(res["label"], [])
        spark = " ".join(
            clr_html("▲", "#ff4444") if s == "HIJACK"
            else clr_html("●", "#00cc66") if s in ("CLEAN", "ACTIVE")
            else clr_html("○", "#ffaa00")
            for s in hist[-10:]
        )
 
        rows += f"""
        <tr style="background:{bg};border-bottom:1px solid #222">
          <td style="padding:10px 14px;font-weight:bold;color:#eee">{res["label"]}</td>
          <td style="padding:10px 14px;color:#aaa;font-size:0.9em">{res["role"]}</td>
          <td style="padding:10px 14px">{badge}</td>
          <td style="padding:10px 14px;color:#ccc;font-size:0.9em">{res["desc"]}{details}</td>
          <td style="padding:10px 14px;font-family:monospace;letter-spacing:3px">{spark}</td>
          <td style="padding:10px 14px;color:#888;font-size:0.8em">{res.get("ts", "—")}</td>
        </tr>"""
 
    alert_banner = ""
    if alerts:
        items = "".join(f'<br>→ {a["label"]} ({a["role"]})' for a in alerts)
        alert_banner = f"""
        <div style="background:#ff4444;color:#000;padding:14px 20px;border-radius:6px;
                    margin-bottom:20px;font-weight:bold;font-size:1.1em">
          ⚠️  ALERTE BGP HIJACK — {len(alerts)} cible(s) compromise(s) !{items}
        </div>"""
 
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="300">
  <title>BGP Monitor — Check #{check_num}</title>
  <style>
    * {{ box-sizing: border-box; margin:0; padding:0; }}
    body {{ background:#0d0d0d; color:#e0e0e0; font-family:'Segoe UI',sans-serif; padding:30px; }}
    h1 {{ color:#00ccff; font-size:1.5em; margin-bottom:4px; }}
    .sub {{ color:#666; font-size:0.85em; margin-bottom:24px; }}
    table {{ width:100%; border-collapse:collapse; border-radius:8px; overflow:hidden; }}
    th {{ background:#1a1a2e; color:#00ccff; text-align:left; padding:10px 14px;
          font-size:0.85em; text-transform:uppercase; letter-spacing:1px; }}
    tr:hover {{ filter:brightness(1.15); }}
    .footer {{ margin-top:20px; color:#444; font-size:0.8em; text-align:center; }}
    .pill {{ display:inline-block; background:#1a1a2e; color:#00ccff;
             border-radius:20px; padding:2px 12px; font-size:0.8em; margin:2px; }}
  </style>
</head>
<body>
  <h1>🛡 BGP Monitor — Orange France</h1>
  <p class="sub">
    <span class="pill">Check #{check_num}</span>
    <span class="pill">{timestamp}</span>
    <span class="pill">AS41128 · AS263692 · 90.98.0.0/15 · 92.183.128.0/18</span>
    <span class="pill">Auto-refresh 5 min</span>
  </p>
  {alert_banner}
  <table>
    <thead>
      <tr>
        <th>Ressource</th><th>Rôle</th><th>Statut</th>
        <th>Détails</th><th>Historique (10 derniers)</th><th>Heure</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="footer">
    BGP Monitor v2.1 · Sources: RIPEstat API · Logs: bgp_monitor.log · bgp_alerts.log
  </div>
</body>
</html>"""
 
 
# ── Arguments CLI ──────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="BGP Monitor — Détection de hijack en temps réel via RIPEstat"
    )
    parser.add_argument(
        "--refresh", type=int, default=None,
        help="Intervalle de vérification en secondes (défaut: config.json ou 300)"
    )
    parser.add_argument(
        "--webhook", type=str, default=None,
        help="URL webhook Discord/Slack pour les alertes HIJACK"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Effectue une seule vérification puis quitte (utile pour CI/CD)"
    )
    return parser.parse_args()
 
 
# ── Main loop ──────────────────────────────────────────────────
def main():
    args   = parse_args()
    config = load_config()
 
    # Priorité : argument CLI > config.json > défaut
    refresh     = args.refresh or config.get("refresh_seconds", 300)
    webhook_url = args.webhook or config.get("webhook_url")
    targets     = config["targets"]
 
    history = {t["label"]: [] for t in targets}
 
    os.system("cls" if os.name == "nt" else "clear")
    h1("BGP MONITOR v2.1 — Orange France Investigation")
    print(f"  {clr('AS41128 · AS263692 · 90.98.0.0/15 · 92.183.128.0/18', CYN)}")
    print(
        f"  {clr(f'Refresh {refresh}s  |  HTML: bgp_report.html  |  CTRL+C pour arrêter', DIM)}"
    )
    if webhook_url:
        print(f"  {clr(f'Webhook actif : {webhook_url[:50]}...', DIM, GRN)}")
    print()
 
    check_num = 0
 
    # FIX : utilisation de context managers pour garantir la fermeture des fichiers
    with (
        open("bgp_monitor.log", "a", encoding="utf-8") as log_file,
        open("bgp_alerts.log",  "a", encoding="utf-8") as alert_file,
    ):
        try:
            while True:
                check_num += 1
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
 
                h2(f"Vérification #{check_num}  ·  {ts}")
 
                results         = []
                alert_triggered = False
 
                for i, target in enumerate(targets, 1):
                    print(
                        clr(f"  [{i}/{len(targets)}] Interrogation {target['label']}...", DIM),
                        end="\r",
                    )
                    res = analyse(target)
                    results.append(res)
 
                    # Historique en mémoire (max 20 entrées par cible)
                    history[target["label"]].append(res["status"])
                    if len(history[target["label"]]) > 20:
                        history[target["label"]].pop(0)
 
                    # Log général
                    log_file.write(f"[{ts}] {res['label']} → {res['status']}\n")
                    log_file.flush()
 
                    if res["status"] == "HIJACK":
                        alert_triggered = True
                        alert_file.write(f"[{ts}] ⚠ HIJACK DÉTECTÉ — {res['label']}\n")
                        alert_file.flush()
 
                # Effacer la ligne de progression
                print(" " * 60, end="\r")
 
                # Affichage terminal
                for i, res in enumerate(results, 1):
                    print_result(res, i)
 
                # Résumé
                sep("─", 70, YLW)
                hijacks = [r for r in results if r["status"] == "HIJACK"]
                if hijacks:
                    print(
                        f"  {badge_ko('⚠  ALERTES ACTIVES')}  "
                        f"{clr(len(hijacks), RED, BOLD)} cible(s) compromise(s)"
                    )
                    for h in hijacks:
                        print(f"    {clr('→', RED)} {clr(h['label'], BOLD, RED)}  {clr(h['role'], DIM)}")
 
                    # Alerte webhook
                    msg = (
                        f"🚨 BGP HIJACK DÉTECTÉ — {len(hijacks)} cible(s)\n"
                        + "\n".join(f"→ {h['label']} ({h['role']})" for h in hijacks)
                        + f"\n[{ts}]"
                    )
                    send_webhook(webhook_url, msg)
                else:
                    print(
                        f"  {badge_ok('✔  AUCUNE ALERTE')}  "
                        f"{clr('Toutes les cibles sont stables', GRN)}"
                    )
 
                sep("─", 70, YLW)
                print(
                    f"  {clr('Rapport HTML → bgp_report.html', DIM, CYN)}  "
                    f"{clr(f'Prochain check dans {refresh // 60} min {refresh % 60}s', DIM)}"
                )
                print()
 
                # Rapport HTML
                html = generate_html(results, check_num, ts, history)
                with open("bgp_report.html", "w", encoding="utf-8") as f:
                    f.write(html)
 
                if args.once:
                    break
 
                time.sleep(refresh)
 
        except KeyboardInterrupt:
            print(f"\n  {clr('Surveillance arrêtée proprement.', YLW)}")
 
 
if __name__ == "__main__":
    main()