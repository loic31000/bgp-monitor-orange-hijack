# 🛡️ BGP Monitor — Orange France Hijack Investigation

![Python](https://img.shields.io/badge/Python-3.12+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Hijack-ACTIVE%20J%2B7-red?style=flat-square)
![Source](https://img.shields.io/badge/Data-RIPEstat%20API-orange?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)

> Real-time BGP hijack detection tool built during the **AS41128 / Orange France** incident.  
> Passive monitoring only — 100% public APIs, no active scanning, legally safe.

---

## 🚨 The Incident

Since **February 25, 2026**, the prefix `90.98.0.0/15` (**131,072 IP addresses** belonging to
Orange France / AS3215) has been fraudulently announced by **AS41128 (ORANGEFR-GRX-AS)**,
silently redirecting traffic toward **Hivelocity Dallas TX (AS29802)**.

### Timeline

| Date | Event |
|---|---|
| 2026-02-25 08:00 UTC | First fraudulent announcement by AS41128 — undetected for 47 days |
| 2026-04-13 16:27 UTC | Mass injection — **1,088 BGP announcements in 5 minutes** |
| 2026-04-13 | 328/329 RIPE peers see the fraudulent route (**99.7% global visibility**) |
| 2026-04-14 | Confirmed by **[Doug Madory](https://twitter.com/DougMadory)** (Kentik) |
| 2026-04-16 | Flagged by **[Spamhaus](https://twitter.com/spamhaus)** |
| 2026-04-20 | **Hijack still active — J+7** |

### Key metrics

```
Prefix targeted   : 90.98.0.0/15 (131,072 IPs)
Fraudulent origin : AS41128 (ORANGEFR-GRX-AS)
Legitimate owner  : AS3215 (Orange France)
Traffic sink      : AS29802 (Hivelocity, Dallas TX)
RPKI status       : UNKNOWN (0% valid ROA)
Global visibility : 99.7% (328/329 RIPE RIS peers)
Duration          : 54+ days
```

---

## 🔍 What this tool does

- **Polls RIPEstat API** every 5 minutes — fully passive, no active scanning
- **Detects fraudulent ASN origins** on monitored prefixes in real time
- **Color-coded terminal output** with status badges (HIJACK / CLEAN / ACTIVE / SILENT)
- **Auto-generates a live HTML dashboard** (`bgp_report.html`) with 5-min auto-refresh
- **Sparkline history** — visual trend of the last 10 checks per target
- **Persistent logs** — `bgp_monitor.log` + `bgp_alerts.log`
- **Rate-limit safe** — sequential requests with proper error handling

---

## 🎯 Monitored targets

| Resource | Role | Status |
|---|---|---|
| `90.98.0.0/15` | Hijacked prefix | 🔴 HIJACK ACTIVE |
| `92.183.128.0/18` | Secondary target (pre-positioned) | 🟡 WATCH |
| AS41128 | Fraudulent origin (compromised ASN) | 🔴 ACTIVE |
| AS3215 | Legitimate owner — Orange France | 🟢 NORMAL |
| AS29802 | Traffic sink — Hivelocity Dallas TX | 🟢 ACTIVE |

---

## ⚙️ Installation

### Windows (PowerShell)

```powershell
# 1. Install Python 3.12 (if not already installed)
winget install Python.Python.3.12

# 2. Close and reopen PowerShell, then verify
python --version

# 3. Clone or download this repo
git clone https://github.com/YOUR_USERNAME/bgp-monitor-orange-hijack.git
cd bgp-monitor-orange-hijack

# 4. Install dependencies
pip install requests

# 5. Run the monitor
python bgp_monitor.py
```

### Linux / macOS

```bash
git clone https://github.com/YOUR_USERNAME/bgp-monitor-orange-hijack.git
cd bgp-monitor-orange-hijack
pip3 install requests
python3 bgp_monitor.py
```

### Suppress deprecation warnings (Python 3.14+)

```powershell
python -W ignore bgp_monitor.py
```

---

## 📊 Output

### Terminal
```
══════════════════════════════════════════════════════════════════════
  BGP MONITOR v2.0 — Orange France Investigation
══════════════════════════════════════════════════════════════════════

  [1]  90.98.0.0/15  (Préfixe hijacké)   ⚠ HIJACK DÉTECTÉ
       Origines  : 41128
       Visibilité: 328/329 peers (99.7%)

  [2]  AS3215  (Orange légitime)   ✔ ACTIF
       Préfixes annoncés : 986
```

### HTML Dashboard
Open `bgp_report.html` in any browser — auto-refreshes every 5 minutes.

---

## 🗂️ Project structure

```
bgp-monitor-orange-hijack/
├── bgp_monitor.py       # Main monitoring script
├── README.md            # This file
├── .gitignore           # Excludes logs and generated files
└── (generated)
    ├── bgp_monitor.log  # Full check history
    ├── bgp_alerts.log   # Hijack alerts only
    └── bgp_report.html  # Live HTML dashboard
```

---

## 🔗 References & Sources

- [RIPEstat — 90.98.0.0/15 routing status](https://stat.ripe.net/resource/90.98.0.0/15)
- [bgp.tools — AS41128](https://bgp.tools/as/41128)
- [Cloudflare Radar — AS41128](https://radar.cloudflare.com/routing/as41128)
- [Spamhaus alert — April 16, 2026](https://twitter.com/spamhaus)
- [Doug Madory / Kentik confirmation](https://twitter.com/DougMadory)
- [RIPEstat Data API documentation](https://stat.ripe.net/docs/data-api)

---

## ⚖️ Legal & Ethics

This tool uses **passive observation only** via public APIs:
- No port scanning
- No active probing or connection attempts to monitored hosts
- No traffic interception
- Compliant with French law (Code pénal art. 323) and EU regulations

Data sources: RIPEstat (RIPE NCC public API) — same data used by CERT-FR, Kentik, Cloudflare.

---

## 📄 License

MIT — free to use, modify and distribute with attribution.

---

*Built with Python · RIPEstat API · Developed during a live BGP hijack investigation — April 2026*
