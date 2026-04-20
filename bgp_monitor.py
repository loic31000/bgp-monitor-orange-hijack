#!/usr/bin/env python3
# bgp_monitor.py — Version 2.0 — Terminal Pro + Rapport HTML auto
import requests, time, json, os
from datetime import datetime, timezone

# ── Couleurs ANSI ──────────────────────────────────────────────
R  = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[2m"
RED  = "\033[91m"
GRN  = "\033[92m"
YLW  = "\033[93m"
BLU  = "\033[94m"
MGT  = "\033[95m"
CYN  = "\033[96m"
WHT  = "\033[97m"
BG_RED   = "\033[41m"
BG_GRN   = "\033[42m"
BG_YLW   = "\033[43m"
BG_BLU   = "\033[44m"
BG_DARK  = "\033[100m"

def clr(text, *codes): return "".join(codes) + str(text) + R
def badge_ok(t):    return clr(f" {t} ", BG_GRN, BOLD, WHT)
def badge_ko(t):    return clr(f" {t} ", BG_RED, BOLD, WHT)
def badge_warn(t):  return clr(f" {t} ", BG_YLW, BOLD, WHT)
def badge_info(t):  return clr(f" {t} ", BG_BLU, BOLD, WHT)
def badge_dim(t):   return clr(f" {t} ", BG_DARK, WHT)

def sep(char="─", n=70, color=CYN): print(clr(char * n, color))
def h1(text): sep("═"); print(clr(f"  {text}", BOLD, CYN)); sep("═")
def h2(text): sep(); print(clr(f"  {text}", BOLD, WHT)); sep()

# ── Cibles de surveillance ─────────────────────────────────────
TARGETS = [
    {"label": "90.98.0.0/15",      "type": "prefix", "resource": "90.98.0.0/15",
     "role": "Préfixe hijacké",    "legit_asn": "3215",
     "hijack_asn": "41128",        "desc": "Orange France — Espace IP légitime"},
    {"label": "92.183.128.0/18",   "type": "prefix", "resource": "92.183.128.0/18",
     "role": "Cible secondaire",   "legit_asn": "3215",
     "hijack_asn": "263692",       "desc": "Orange France — Pré-positionnement"},
    {"label": "AS41128",           "type": "asn",    "resource": "41128",
     "role": "Origine frauduleuse","legit_asn": None,
     "hijack_asn": "41128",        "desc": "ORANGEFR-GRX-AS — ASN compromis"},
    {"label": "AS3215",            "type": "asn",    "resource": "3215",
     "role": "Orange légitime",    "legit_asn": "3215",
     "hijack_asn": None,           "desc": "Orange France — Propriétaire réel"},
    {"label": "AS29802",           "type": "asn",    "resource": "29802",
     "role": "Destination finale", "legit_asn": None,
     "hijack_asn": None,           "desc": "Hivelocity Dallas TX — Infra réelle"},
]

# Historique en mémoire (max 20 checks par cible)
HISTORY = {t["label"]: [] for t in TARGETS}

# ── API RIPEstat ───────────────────────────────────────────────
def fetch_prefix(prefix):
    try:
        url = f"https://stat.ripe.net/data/routing-status/data.json?resource={prefix}"
        r = requests.get(url, timeout=10)
        d = r.json().get("data", {})
        origins = [str(o.get("origin", "")) for o in d.get("origins", [])]
        peers   = d.get("visibility", {})
        total   = peers.get("total_ris_peers", 0)
        visible = peers.get("ris_peers_seeing", 0)
        return {"origins": origins, "visible": visible, "total": total,
                "last_update": d.get("last_update", "—")}
    except Exception as e:
        return {"error": str(e)}

def fetch_asn(asn):
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        r = requests.get(url, timeout=10)
        d = r.json().get("data", {})
        prefixes = d.get("prefixes", [])
        return {"prefix_count": len(prefixes), "asn": asn}
    except Exception as e:
        return {"error": str(e)}

# ── Analyse d'une cible ────────────────────────────────────────
def analyse(target):
    result = {"label": target["label"], "role": target["role"],
              "desc": target["desc"], "ts": datetime.now(timezone.utc).replace(tzinfo=None).strftime("%H:%M:%S UTC")}

    if target["type"] == "prefix":
        data = fetch_prefix(target["resource"])
        if "error" in data:
            result.update({"status": "ERROR", "detail": data["error"]})
            return result
        origins = data["origins"]
        visible = data["visible"]
        total   = data["total"]
        pct     = round(visible / total * 100, 1) if total else 0
        hijack_asn = target["hijack_asn"]

        if hijack_asn and hijack_asn in origins:
            status = "HIJACK"
        elif visible > 50 and hijack_asn and hijack_asn in origins:
            status = "HIJACK"
        else:
            status = "CLEAN"

        result.update({
            "status": status,
            "origins": origins,
            "visible": visible,
            "total": total,
            "pct": pct,
            "last_update": data["last_update"],
        })

    else:  # ASN
        data = fetch_asn(target["resource"])
        if "error" in data:
            result.update({"status": "ERROR", "detail": data["error"]})
            return result
        count = data["prefix_count"]
        result.update({
            "status": "ACTIVE" if count > 0 else "SILENT",
            "prefix_count": count,
        })

    return result

# ── Affichage terminal ─────────────────────────────────────────
def print_result(res, idx):
    label  = res["label"]
    status = res["status"]
    role   = res["role"]
    desc   = res["desc"]

    # Badge statut
    if status == "HIJACK":
        b = badge_ko("⚠  HIJACK DÉTECTÉ")
    elif status == "CLEAN":
        b = badge_ok("✔  CLEAN")
    elif status == "ACTIVE":
        b = badge_ok("✔  ACTIF")
    elif status == "SILENT":
        b = badge_warn("~  SILENCIEUX")
    else:
        b = badge_dim("?  ERREUR")

    # Ligne principale
    print(f"  {clr(f'[{idx}]', DIM, CYN)}  {clr(label, BOLD, WHT)}  {clr(f'({role})', DIM)}  {b}")
    print(f"       {clr(desc, DIM)}")

    if "origins" in res:
        orig_str = ", ".join(res["origins"]) if res["origins"] else "aucune"
        color = RED if status == "HIJACK" else GRN
        vis_color = RED if res["pct"] > 50 and status == "HIJACK" else GRN
        print(f"       Origines  : {clr(orig_str, color, BOLD)}")
        print(f"       Visibilité: {clr(f"{res['visible']}/{res['total']} peers", vis_color)} "
              f"{clr(f"({res['pct']}%)", BOLD, vis_color)}")
        print(f"       Dernière MAJ : {clr(res.get('last_update', '—'), DIM)}")

    if "prefix_count" in res:
        c = res["prefix_count"]
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

def generate_html(results, check_num, timestamp):
    rows = ""
    alerts = [r for r in results if r["status"] == "HIJACK"]

    for res in results:
        status = res["status"]
        fg, bg = STATUS_COLORS.get(status, ("#aaa", "#111"))
        badge = f'''<span style="background:{fg};color:#000;padding:3px 10px;border-radius:4px;font-weight:bold;font-size:0.85em">{status}</span>'''

        details = ""
        if "origins" in res:
            orig = ", ".join(res["origins"]) or "aucune"
            details = f'''<br><small>Origines: <b>{orig}</b> | Visibilité: {res["visible"]}/{res["total"]} ({res["pct"]}%)</small>'''
        if "prefix_count" in res:
            details = f'''<br><small>Préfixes annoncés: <b>{res["prefix_count"]}</b></small>'''

        # Historique sparkline texte
        hist = HISTORY[res["label"]]
        spark = " ".join(
            clr_html("▲", "#ff4444") if s == "HIJACK"
            else clr_html("●", "#00cc66") if s in ("CLEAN","ACTIVE")
            else clr_html("○", "#ffaa00")
            for s in hist[-10:]
        )

        rows += f'''
        <tr style="background:{bg};border-bottom:1px solid #222">
          <td style="padding:10px 14px;font-weight:bold;color:#eee">{res["label"]}</td>
          <td style="padding:10px 14px;color:#aaa;font-size:0.9em">{res["role"]}</td>
          <td style="padding:10px 14px">{badge}</td>
          <td style="padding:10px 14px;color:#ccc;font-size:0.9em">{res["desc"]}{details}</td>
          <td style="padding:10px 14px;font-family:monospace;letter-spacing:3px">{spark}</td>
          <td style="padding:10px 14px;color:#888;font-size:0.8em">{res.get("ts","—")}</td>
        </tr>'''

    alert_banner = ""
    if alerts:
        alert_banner = f'''
        <div style="background:#ff4444;color:#000;padding:14px 20px;border-radius:6px;
                    margin-bottom:20px;font-weight:bold;font-size:1.1em">
          ⚠️  ALERTE BGP HIJACK — {len(alerts)} cible(s) compromise(s) !
          {"".join(f'<br>→ {a["label"]} ({a["role"]})' for a in alerts)}
        </div>'''

    html = f'''<!DOCTYPE html>
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
    BGP Monitor v2.0 · Sources: RIPEstat API · Logs: bgp_monitor.log · bgp_alerts.log
  </div>
</body>
</html>'''
    return html

def clr_html(sym, color):
    return f'<span style="color:{color}">{sym}</span>'

# ── Main loop ──────────────────────────────────────────────────
def main():
    REFRESH = 300
    check_num = 0
    LOG   = open("bgp_monitor.log",   "a", encoding="utf-8")
    ALERT = open("bgp_alerts.log",    "a", encoding="utf-8")

    os.system("cls" if os.name == "nt" else "clear")
    h1("BGP MONITOR v2.0 — Orange France Investigation")
    print(f"  {clr('AS41128 · AS263692 · 90.98.0.0/15 · 92.183.128.0/18', CYN)}")
    print(f"  {clr('Refresh 5 min  |  Rapport HTML: bgp_report.html  |  CTRL+C pour arrêter', DIM)}")
    print()

    try:
        while True:
            check_num += 1
            ts = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S UTC")
            ts_short = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%H:%M:%S")

            h2(f"Vérification #{check_num}  ·  {ts}")

            results = []
            alert_triggered = False

            for i, target in enumerate(TARGETS, 1):
                print(clr(f"  [{i}/{len(TARGETS)}] Interrogation {target['label']}...", DIM), end="\r")
                res = analyse(target)
                results.append(res)

                # Historique
                HISTORY[target["label"]].append(res["status"])
                if len(HISTORY[target["label"]]) > 20:
                    HISTORY[target["label"]].pop(0)

                # Log
                LOG.write(f"[{ts}] {res['label']} → {res['status']}\n")
                LOG.flush()

                if res["status"] == "HIJACK":
                    alert_triggered = True
                    ALERT.write(f"[{ts}] ⚠ HIJACK DÉTECTÉ — {res['label']}\n")
                    ALERT.flush()

            # Effacer la ligne de progression
            print(" " * 60, end="\r")

            # Affichage terminal
            for i, res in enumerate(results, 1):
                print_result(res, i)

            # Résumé
            sep("─", 70, YLW)
            hijacks = [r for r in results if r["status"] == "HIJACK"]
            if hijacks:
                print(f"  {badge_ko('⚠  ALERTES ACTIVES')}  {clr(len(hijacks), RED, BOLD)} cible(s) compromise(s)")
                for h in hijacks:
                    print(f"    {clr('→', RED)} {clr(h['label'], BOLD, RED)}  {clr(h['role'], DIM)}")
            else:
                print(f"  {badge_ok('✔  AUCUNE ALERTE')}  {clr('Toutes les cibles sont stables', GRN)}")
            sep("─", 70, YLW)
            print(f"  {clr(f'Rapport HTML → bgp_report.html', DIM, CYN)}  "
                  f"{clr(f'Prochain check dans {REFRESH//60} min', DIM)}")
            print()

            # Rapport HTML
            html = generate_html(results, check_num, ts)
            with open("bgp_report.html", "w", encoding="utf-8") as f:
                f.write(html)

            time.sleep(REFRESH)

    except KeyboardInterrupt:
        print(f"\n  {clr('Surveillance arrêtée.', YLW)}")
        LOG.close(); ALERT.close()

if __name__ == "__main__":
    main()
