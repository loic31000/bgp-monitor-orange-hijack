#!/usr/bin/env python3
# bgp_monitor.py — Version 2.4 — Hijack massif 167.32.0.0/16
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
    "targets": [
        # === HIJACK ORANGE (enquête principale) ===
        {
            "label": "90.98.0.0/15",
            "type": "prefix",
            "resource": "90.98.0.0/15",
            "role": "Préfixe hijacké (Orange)",
            "legit_asn": "3215",
            "hijack_asn": "41128",
            "desc": "Orange France — Espace IP légitime"
        },
        {
            "label": "92.183.128.0/18",
            "type": "prefix",
            "resource": "92.183.128.0/18",
            "role": "Cible secondaire (Orange)",
            "legit_asn": "3215",
            "hijack_asn": "263692",
            "desc": "Orange France — Pré-positionnement"
        },
        {
            "label": "AS41128",
            "type": "asn",
            "resource": "41128",
            "role": "Origine frauduleuse",
            "desc": "ORANGEFR-GRX-AS — ASN compromis"
        },
        {
            "label": "AS3215",
            "type": "asn",
            "resource": "3215",
            "role": "Orange légitime",
            "desc": "Orange France — Propriétaire réel"
        },
        {
            "label": "AS29802",
            "type": "asn",
            "resource": "29802",
            "role": "Destination finale (Hivelocity)",
            "desc": "Hivelocity Dallas TX — Infra réelle"
        },
        # === ROUTES SPAMHAUS (pool MCI/SAE) ===
        {
            "label": "198.193.12.0/24",
            "type": "prefix",
            "resource": "198.193.12.0/24",
            "role": "Route suspecte (MCI/SAE pool)",
            "hijack_asn": "2702",
            "desc": "Pool MCI/SAE — AS2702 dormant depuis 2003"
        },
        {
            "label": "198.195.144.0/24",
            "type": "prefix",
            "resource": "198.195.144.0/24",
            "role": "Route suspecte (MCI/SAE pool)",
            "hijack_asn": "2702",
            "desc": "Pool MCI/SAE — AS2702 dormant"
        },
        {
            "label": "198.196.199.0/24",
            "type": "prefix",
            "resource": "198.196.199.0/24",
            "role": "Route suspecte (MCI/SAE pool)",
            "hijack_asn": "2702",
            "desc": "Pool MCI/SAE — AS2702 dormant"
        },
        # === NOUVEAU : HIJACK MASSIF 167.32.0.0/16 (AS PARLEMENT VOLÉ) ===
        {
            "label": "167.32.0.0/16",
            "type": "prefix",
            "resource": "167.32.0.0/16",
            "role": "HIJACK MASSIF — Parlement canadien volé",
            "hijack_asn": "398290",
            "desc": "AS398290 (House of Commons) volé — Actif depuis nov. 2023 — 331/331 peers"
        },
        {
            "label": "167.32.0.0/21",
            "type": "prefix",
            "resource": "167.32.0.0/21",
            "role": "Sous-préfixe (AS398290)",
            "hijack_asn": "398290",
            "desc": "Détournement massif — Sous-ensemble /21"
        },
        {
            "label": "167.32.2.0/24",
            "type": "prefix",
            "resource": "167.32.2.0/24",
            "role": "Sous-préfixe (AS398290)",
            "hijack_asn": "398290",
            "desc": "Détournement massif — /24"
        },
        {
            "label": "167.32.3.0/24",
            "type": "prefix",
            "resource": "167.32.3.0/24",
            "role": "Sous-préfixe (AS398290)",
            "hijack_asn": "398290",
            "desc": "Détournement massif — /24"
        },
        {
            "label": "167.32.5.0/24",
            "type": "prefix",
            "resource": "167.32.5.0/24",
            "role": "Sous-préfixe (AS398290)",
            "hijack_asn": "398290",
            "desc": "Détournement massif — /24"
        },
        {
            "label": "167.32.6.0/24",
            "type": "prefix",
            "resource": "167.32.6.0/24",
            "role": "Sous-préfixe (AS398290)",
            "hijack_asn": "398290",
            "desc": "Détournement massif — /24"
        },
        {
            "label": "167.32.7.0/24",
            "type": "prefix",
            "resource": "167.32.7.0/24",
            "role": "Sous-préfixe (AS398290)",
            "hijack_asn": "398290",
            "desc": "Détournement massif — /24"
        },
        {
            "label": "167.32.8.0/24",
            "type": "prefix",
            "resource": "167.32.8.0/24",
            "role": "Sous-préfixe (AS398290)",
            "hijack_asn": "398290",
            "desc": "Détournement massif — /24"
        },
        # === AS SUSPECTS ===
        {
            "label": "AS2702",
            "type": "asn",
            "resource": "2702",
            "role": "AS dormant réactivé",
            "desc": "Novx Systems/Interserve — Dormant depuis 2003"
        },
        {
            "label": "AS7857",
            "type": "asn",
            "resource": "7857",
            "role": "AS défunt réactivé",
            "desc": "Empire Communications — Société disparue"
        },
        {
            "label": "AS215828",
            "type": "asn",
            "resource": "215828",
            "role": "Upstream suspect (Allemagne)",
            "desc": "TMW Global Networks — Tizian Maxime Weigt"
        },
        {
            "label": "AS398290",
            "type": "asn",
            "resource": "398290",
            "role": "AS GOUVERNEMENTAL VOLÉ",
            "desc": "House of Commons (Canada) — Volé et utilisé pour hijack BGP"
        },
    ]
}
 
CONFIG_FILE = "config.json"
 
 
def load_config():
    """Charge config.json si présent, sinon retourne la config par défaut."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        cfg = {**DEFAULT_CONFIG, **user_cfg}
        print(clr(f"  Config chargée depuis {CONFIG_FILE}", DIM, GRN))
    else:
        cfg = DEFAULT_CONFIG.copy()
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
        last_seen_origin = d.get("last_seen", {}).get("origin", "")
        if last_seen_origin and last_seen_origin not in origins:
            origins.append(str(last_seen_origin))
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
        # Gestion des erreurs 500, 404, etc.
        return {"error": str(e), "status_code": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None}
 
 
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
        legit_asn  = target.get("legit_asn")
 
        # Détection du hijack : AS frauduleux présent OU AS légitime ABSENT
        hijack_detected = False
        if hijack_asn and hijack_asn in origins:
            hijack_detected = True
        elif legit_asn and legit_asn not in origins and origins:
            hijack_detected = True
 
        if hijack_detected:
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
  <h1>🛡 BGP Monitor — Hijack Massif 167.32.0.0/16 (AS398290) DÉTECTÉ</h1>
  <p class="sub">
    <span class="pill">Check #{check_num}</span>
    <span class="pill">{timestamp}</span>
    <span class="pill">AS41128 · AS2702 · AS7857 · AS215828 · AS398290</span>
    <span class="pill">90.98.0.0/15 · 198.193.0.0/16 · 167.32.0.0/16</span>
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
    BGP Monitor v2.4 · Sources: RIPEstat API · Logs: bgp_monitor.log · bgp_alerts.log
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
        "--once", action="store_true",
        help="Effectue une seule vérification puis quitte (utile pour CI/CD)"
    )
    return parser.parse_args()
 
 
# ── Main loop ──────────────────────────────────────────────────
def main():
    args   = parse_args()
    config = load_config()
 
    refresh     = args.refresh or config.get("refresh_seconds", 300)
    targets     = config["targets"]
 
    history = {t["label"]: [] for t in targets}
 
    os.system("cls" if os.name == "nt" else "clear")
    h1("BGP MONITOR v2.4 — Hijack Massif 167.32.0.0/16 (AS398290)")
    print(f"  {clr('AS41128 · AS2702 · AS7857 · AS215828 · AS398290', CYN)}")
    print(f"  {clr('90.98.0.0/15 · 198.193.0.0/16 · 167.32.0.0/16', CYN)}")
    print(
        f"  {clr(f'Refresh {refresh}s  |  HTML: bgp_report.html  |  CTRL+C pour arrêter', DIM)}"
    )
    print()
 
    check_num = 0
 
    with (
        open("bgp_monitor.log", "a", encoding="utf-8") as log_file,
        open("bgp_alerts.log",  "a", encoding="utf-8") as alert_file,
    ):
        try:
            while True:
                check_num += 1
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
 
                h2(f"Vérification #{check_num}  ·  {ts}")
 
                results = []
 
                for i, target in enumerate(targets, 1):
                    print(
                        clr(f"  [{i}/{len(targets)}] Interrogation {target['label']}...", DIM),
                        end="\r",
                    )
                    res = analyse(target)
                    results.append(res)
 
                    history[target["label"]].append(res["status"])
                    if len(history[target["label"]]) > 20:
                        history[target["label"]].pop(0)
 
                    log_file.write(f"[{ts}] {res['label']} → {res['status']}\n")
                    log_file.flush()
 
                    if res["status"] == "HIJACK":
                        alert_file.write(f"[{ts}] ⚠ HIJACK DÉTECTÉ — {res['label']}\n")
                        alert_file.flush()
 
                print(" " * 60, end="\r")
 
                for i, res in enumerate(results, 1):
                    print_result(res, i)
 
                sep("─", 70, YLW)
                hijacks = [r for r in results if r["status"] == "HIJACK"]
                if hijacks:
                    print(
                        f"  {badge_ko('⚠  ALERTES ACTIVES')}  "
                        f"{clr(len(hijacks), RED, BOLD)} cible(s) compromise(s)"
                    )
                    for h in hijacks:
                        print(f"    {clr('→', RED)} {clr(h['label'], BOLD, RED)}  {clr(h['role'], DIM)}")
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
