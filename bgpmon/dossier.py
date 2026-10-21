"""Dossier de preuves passif pour un couple (préfixe, origine).

`bgpmon dossier PREFIX ASN` rassemble, sans aucun scan actif, ce que disent les
sources publiques d'une annonce : routage RIS (actuel et historique), RPKI
(validation et archives quotidiennes des ROA), IRR, registre RIPE, transferts
officiels du RIPE NCC, DNS inverse (via un résolveur public) et, en option, une
liste d'IP publiée par l'opérateur.

Chaque donnée brute est enregistrée dans `raw/` avec sa source, sa requête, son
horodatage et son empreinte SHA-256. Les adresses e-mail sont masquées. Le module
produit des constats (`summary.json`, `OBSERVATIONS.md`) mais aucune conclusion :
l'interprétation reste humaine.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import lzma
import re
import time
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from bgpmon import __version__
from bgpmon.models import Network, iso, normalize_path, parse_network, strip_prepends, utcnow
from bgpmon.sources import SourceError
from bgpmon.sources.irr import whois_query
from bgpmon.sources.ripestat import RipeStatClient

log = logging.getLogger("bgpmon.dossier")

USER_AGENT = f"bgpmon/{__version__} (collecte passive)"
DEFAULT_IRR = (
    ("RADB", "whois.radb.net", "-s RADB"),
    ("ALTDB", "whois.altdb.net", ""),
    ("RIPE", "whois.ripe.net", "-r"),
)
ROA_ARCHIVE = "https://ftp.ripe.net/rpki/{tal}.tal/{y}/{m}/{d}/roas.csv.xz"
TRANSFERS_URL = "https://ftp.ripe.net/pub/stats/ripencc/transfers/transfers_latest.json"
DOH_URL = "https://cloudflare-dns.com/dns-query"
WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
# Attributs RPSL jamais conservés (secrets ou données de contact).
DROPPED_RPSL = frozenset({"auth", "upd-to", "mnt-nfy", "notify", "e-mail", "phone", "fax-no"})
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_CIDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b|\b[0-9a-fA-F:]+:[0-9a-fA-F:]*/\d{1,3}\b")


# ── Fonctions pures (testées sans réseau) ─────────────────────────────────


def redact(obj: Any) -> Any:
    """Masque les adresses e-mail dans toute structure JSON (le domaine est conservé)."""
    if isinstance(obj, str):
        return _EMAIL.sub(r"<masqué>@\1", obj)
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    return obj


# Champs dont la valeur est masquée d'office : le titulaire d'un ASN (BGPlay `nodes[].owner`)
# est souvent une personne physique, et seul l'ASN sert à l'analyse.
MASKED_FIELDS = frozenset({"owner"})


def mask_fields(obj: Any, keys: frozenset[str] = MASKED_FIELDS) -> Any:
    """Remplace par « <masqué> » les valeurs texte des clés `keys`, à toute profondeur."""
    if isinstance(obj, list):
        return [mask_fields(x, keys) for x in obj]
    if isinstance(obj, dict):
        return {
            k: "<masqué>" if k in keys and isinstance(v, str) else mask_fields(v, keys)
            for k, v in obj.items()
        }
    return obj


def parse_rpsl_objects(text: str) -> list[dict[str, list[str]]]:
    """Objets RPSL (attribut → valeurs), sans commentaires ni attributs sensibles."""
    objects: list[dict[str, list[str]]] = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        obj: dict[str, list[str]] = {}
        last: str | None = None
        for line in block.split("\n"):
            if not line or line.startswith(("%", "#")):
                continue
            if line[0] in " \t+" and last:
                obj[last][-1] = f"{obj[last][-1]} {line.lstrip('+').strip()}".strip()
                continue
            name, sep, value = line.partition(":")
            if not sep:
                continue
            last = name.strip().lower()
            obj.setdefault(last, []).append(value.strip())
        obj = {k: v for k, v in obj.items() if k not in DROPPED_RPSL}
        if obj:
            objects.append(redact(obj))
    return objects


def upstreams(paths: Iterable[list[Any]], origin: int) -> Counter[int]:
    """Distribution de l'ASN adjacent à `origin` (prepending retiré)."""
    counts: Counter[int] = Counter()
    for raw in paths:
        path = strip_prepends(normalize_path(raw))
        if len(path) >= 2 and path[-1] == origin and isinstance(path[-2], int):
            counts[path[-2]] += 1
    return counts


def compare_upstreams(target: Counter[int], reference: Counter[int]) -> dict[str, Any]:
    total = sum(target.values()) or 1
    return {
        "share_of_target_routes_via_reference_upstreams_pct": round(
            100 * sum(n for a, n in target.items() if a in reference) / total, 1
        ),
        "reference_upstreams_absent_from_target": [
            {"asn": a, "reference_routes": n} for a, n in reference.most_common() if a not in target
        ],
        "target_upstreams_absent_from_reference": [
            {"asn": a, "routes": n} for a, n in target.most_common() if a not in reference
        ],
    }


def history_spans(data: dict[str, Any], granularity: int | None = None) -> list[dict[str, Any]]:
    """Résume un `routing-history` en périodes continues par (origine, préfixe)."""
    gran = granularity or int(data.get("time_granularity") or 0)
    spans: list[dict[str, Any]] = []
    for by_origin in data.get("by_origin") or []:
        origin = int(by_origin["origin"])
        for entry in by_origin.get("prefixes") or []:
            tls = sorted(entry.get("timelines") or [], key=lambda t: t["starttime"])
            current: dict[str, Any] | None = None
            for tl in tls:
                start, end = tl["starttime"], tl["endtime"]
                peers = float(tl.get("full_peers_seeing") or 0)
                contiguous = (
                    current is not None
                    and (_ts(start) - _ts(current["end"])).total_seconds() <= max(gran, 1) + 1
                )
                if current is not None and contiguous:
                    current["end"] = end
                    current["max_peers"] = max(current["max_peers"], peers)
                    current["min_peers"] = min(current["min_peers"], peers)
                    current["bins"] += 1
                else:
                    if current is not None:
                        spans.append(current)
                    current = {
                        "origin": origin,
                        "prefix": entry["prefix"],
                        "start": start,
                        "end": end,
                        "max_peers": peers,
                        "min_peers": peers,
                        "bins": 1,
                    }
            if current is not None:
                spans.append(current)
    return sorted(spans, key=lambda s: (s["start"], s["prefix"], s["origin"]))


def appearance(bgplay: dict[str, Any], origin: int) -> dict[str, Any]:
    """Première annonce, chemin initial et upstreams heure par heure dans une fenêtre BGPlay."""
    events = sorted(bgplay.get("events") or [], key=lambda e: e["timestamp"])
    announces = [e for e in events if e.get("type") == "A"]
    hourly: dict[str, Counter[int]] = {}
    for e in announces:
        hour = e["timestamp"][:13]
        hourly.setdefault(hour, Counter()).update(upstreams([e["attrs"]["path"]], origin))
    first = announces[0] if announces else None
    return {
        "initial_state_routes": len(bgplay.get("initial_state") or []),
        "events": len(events),
        "first_announcement": first["timestamp"] if first else None,
        "first_path": first["attrs"]["path"] if first else None,
        "peers_announcing": len({e["attrs"]["source_id"] for e in announces}),
        "hourly_upstreams": [
            {"hour": h, "announcements": sum(c.values()), "upstreams": c.most_common(6)}
            for h, c in sorted(hourly.items())
        ],
    }


def withdrawal(bgplay: dict[str, Any]) -> dict[str, Any]:
    """Déroulé d'un retrait : peers initiaux, premier/dernier retrait, peers restants."""
    seen = {s["source_id"]: True for s in bgplay.get("initial_state") or []}
    events = sorted(bgplay.get("events") or [], key=lambda e: e["timestamp"])
    for e in events:
        seen[e["attrs"]["source_id"]] = e.get("type") == "A"
    withdrawals = [e["timestamp"] for e in events if e.get("type") == "W"]
    return {
        "initial_peers": len(bgplay.get("initial_state") or []),
        "first_withdrawal": withdrawals[0] if withdrawals else None,
        "median_withdrawal": withdrawals[len(withdrawals) // 2] if withdrawals else None,
        "last_withdrawal": withdrawals[-1] if withdrawals else None,
        "peers_still_announcing_at_window_end": sum(seen.values()),
    }


def filter_roas(csv_text: str, scope: Network) -> list[dict[str, str]]:
    rows = []
    for r in csv.DictReader(io.StringIO(csv_text)):
        try:
            net = ipaddress.ip_network(r["IP Prefix"])
        except (KeyError, ValueError):
            continue
        if net.version == scope.version and (net.subnet_of(scope) or net.supernet_of(scope)):  # type: ignore[arg-type]
            rows.append(
                {
                    "asn": r.get("ASN", ""),
                    "prefix": str(net),
                    "max_length": r.get("Max Length", ""),
                    "not_before": r.get("Not Before", ""),
                    "not_after": r.get("Not After", ""),
                }
            )
    return sorted(rows, key=lambda x: (x["prefix"], x["asn"], x["max_length"]))


def _range_networks(item: dict[str, Any]) -> list[Network]:
    try:
        return list(
            ipaddress.summarize_address_range(
                ipaddress.ip_address(item["start_address"]),
                ipaddress.ip_address(item["end_address"]),
            )
        )
    except (KeyError, ValueError, TypeError):
        return []


def filter_transfers(
    transfers: list[dict[str, Any]], scope: Network | None = None, org_name: str | None = None
) -> list[dict[str, Any]]:
    """Transferts RIPE NCC recouvrant `scope`, ou impliquant l'organisation `org_name`."""
    out = []
    needle = (org_name or "").lower()
    for t in transfers:
        names = " | ".join(
            str((t.get(k) or {}).get("name") or "")
            for k in ("source_organization", "recipient_organization")
        ).lower()
        nets = [
            n
            for key in ("ip4nets", "ip6nets")
            for part in ("original_set", "transfer_set")
            for item in (t.get(key) or {}).get(part, [])
            for n in _range_networks(item)
        ]
        hit_scope = scope is not None and any(
            n.version == scope.version and n.overlaps(scope) for n in nets
        )
        if hit_scope or (needle and needle in names):
            out.append(t)
    return out


def cidrs_overlapping(text: str, scope: Network) -> list[str]:
    hits = []
    for m in _CIDR.findall(text):
        try:
            net = ipaddress.ip_network(m, strict=False)
        except ValueError:
            continue
        if net.version == scope.version and net.overlaps(scope):
            hits.append(str(net))
    return sorted(set(hits))


def reverse_zone(network: Network) -> str:
    """Zone in-addr.arpa (frontière d'octet) contenant le réseau, pour IPv4."""
    octets = str(network.network_address).split(".")
    keep = max(1, network.prefixlen // 8)
    return ".".join(reversed(octets[:keep])) + ".in-addr.arpa"


def ptr_sample(network: Network, count: int) -> list[str]:
    """`count` adresses .1 réparties régulièrement dans le préfixe (aucun balayage)."""
    if network.version != 4 or count <= 0:
        return []
    subnets = list(network.subnets(new_prefix=24)) if network.prefixlen <= 24 else [network]
    step = max(1, len(subnets) // count)
    return [str(s.network_address + 1) for s in subnets[::step][:count]]


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)


def _fmt(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M")


# ── Collecte ──────────────────────────────────────────────────────────────


def _http_get(url: str, timeout: float = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body: bytes = resp.read()
    return gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body


class Dossier:
    def __init__(
        self,
        out_dir: str | Path,
        ripestat: RipeStatClient,
        whois: Callable[[str, int, str, float], str] = whois_query,
        http: Callable[[str], bytes] = _http_get,
        pause: float = 0.3,
    ):
        self.out = Path(out_dir)
        self.raw = self.out / "raw"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.ripestat = ripestat
        self._whois = whois
        self._http = http
        self._pause = pause
        self.index: list[dict[str, Any]] = []
        self.unverified: list[str] = []

    # ── Enregistrement ──
    def save(self, name: str, source: str, query: str, data: Any, note: str = "") -> str:
        fetched = iso()
        # Aller-retour JSON : clés entières → chaînes, pour que l'empreinte calculée ici
        # soit identique à celle recalculée en relisant le fichier.
        payload = json.loads(json.dumps(mask_fields(redact(data)), ensure_ascii=False, default=str))
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        meta = {
            "source": source,
            "query": query,
            "fetched_at": fetched,
            "sha256_data": digest,
            "tool": f"bgpmon {__version__}",
            "note": note,
        }
        path = self.raw / f"{name}.json"
        path.write_text(
            json.dumps({"meta": meta, "data": payload}, ensure_ascii=False, indent=1, default=str),
            encoding="utf-8",
        )
        self.index.append({"file": f"raw/{name}.json", **meta})
        return digest

    def fail(self, what: str, exc: Exception) -> None:
        msg = f"{what} : {type(exc).__name__}: {exc}"
        log.warning("Non vérifié — %s", msg)
        self.unverified.append(msg)

    def stat(self, name: str, endpoint: str, **params: Any) -> dict[str, Any] | None:
        query = f"{endpoint} " + " ".join(f"{k}={v}" for k, v in params.items())
        try:
            body = self.ripestat.get_body(endpoint, **params)
        except SourceError as exc:
            self.fail(f"RIPEstat {query}", exc)
            return None
        self.save(
            name,
            "RIPEstat https://stat.ripe.net/data/",
            query,
            {"messages": body.get("messages"), "data": body.get("data")},
        )
        data: dict[str, Any] = body["data"]
        return data

    def whois(self, name: str, host: str, query: str) -> list[dict[str, list[str]]] | None:
        try:
            text = self._whois(host, 43, query, 30.0)
        except OSError as exc:
            self.fail(f"whois {host} « {query} »", exc)
            return None
        objects = parse_rpsl_objects(text)
        errors = [ln for ln in text.splitlines() if ln.startswith("%ERROR")]
        self.save(name, f"whois {host}:43", query, {"objects": objects, "errors": errors})
        time.sleep(self._pause)
        return objects

    def fetch(self, url: str) -> bytes | None:
        try:
            return self._http(url)
        except Exception as exc:  # noqa: BLE001 — toute erreur réseau devient « non vérifié »
            self.fail(f"GET {url}", exc)
            return None

    def fetch_retry(self, url: str, attempts: int = 3, delay: float = 10.0) -> bytes | None:
        """Pour les services qui limitent le débit (Wayback Machine) : quelques reprises."""
        for i in range(attempts):
            try:
                return self._http(url)
            except Exception as exc:  # noqa: BLE001
                if i == attempts - 1:
                    self.fail(f"GET {url}", exc)
                else:
                    time.sleep(delay * (i + 1))
        return None

    # ── Étapes ──
    def _refine(
        self, prefix: str, origin: int, start: datetime, end: datetime, label: str
    ) -> list[dict[str, Any]]:
        """Périodes à granularité fine pour (préfixe, origine) sur une fenêtre courte."""
        d = self.stat(
            f"routing_history_{label}",
            "routing-history",
            resource=prefix,
            starttime=_fmt(start),
            endtime=_fmt(min(end, utcnow())),
        )
        return [
            s for s in history_spans(d or {}) if s["prefix"] == prefix and s["origin"] == origin
        ]

    def routing(self, prefix: str, asn: int, covering: str, reference: int) -> dict[str, Any]:
        now = utcnow()
        res: dict[str, Any] = {}
        for label, res_prefix in (("prefix", prefix), ("covering", covering)):
            d = self.stat(f"routing_status_{label}", "routing-status", resource=res_prefix)
            if d:
                vis = (d.get("visibility") or {}).get("v4" if ":" not in prefix else "v6") or {}
                res[f"status_{label}"] = {
                    "query_time": d.get("query_time"),
                    "origins": [o.get("origin") for o in d.get("origins") or []],
                    "more_specifics": d.get("more_specifics"),
                    "less_specifics": d.get("less_specifics"),
                    "peers_seeing": vis.get("ris_peers_seeing"),
                    "total_peers": vis.get("total_ris_peers"),
                    "first_seen": d.get("first_seen"),
                    "last_seen": d.get("last_seen"),
                }
        full = self.stat("routing_history_full", "routing-history", resource=covering)
        recent = self.stat(
            "routing_history_400d",
            "routing-history",
            resource=covering,
            starttime=_fmt(now - timedelta(days=400)),
            endtime=_fmt(now),
        )
        res["history_full"] = history_spans(full) if full else None
        res["history_400d"] = history_spans(recent) if recent else None
        spans = [
            s
            for s in (res["history_400d"] or res["history_full"] or [])
            if s["prefix"] == prefix and s["origin"] == asn
        ]
        res["target_spans"] = spans
        if spans:
            # La granularité de l'historique long (jusqu'à plusieurs jours) est trop
            # grossière pour BGPlay : on affine sur une fenêtre courte (≈ 8 h).
            coarse = _ts(spans[0]["start"])
            fine = self._refine(
                prefix, asn, coarse - timedelta(days=1), coarse + timedelta(days=3), "appearance"
            )
            first = _ts(fine[0]["start"]) if fine else coarse
            res["first_seen_refined"] = fine[0]["start"] if fine else None
            bp = self.stat(
                "bgplay_appearance",
                "bgplay",
                resource=prefix,
                starttime=_fmt(first - timedelta(hours=8)),
                endtime=_fmt(first + timedelta(hours=24)),
            )
            res["appearance"] = appearance(bp, asn) if bp else None
        # Disparitions récentes d'autres routes du préfixe englobant (retraits)
        ended = [
            s
            for s in res["history_400d"] or []
            if _ts(s["end"]) < now - timedelta(days=1)
            and not (s["prefix"] == prefix and s["origin"] == asn)
            and s["max_peers"] >= 50
        ]
        res["withdrawals"] = []
        for i, s in enumerate(sorted(ended, key=lambda x: x["end"], reverse=True)[:3]):
            coarse_end = _ts(s["end"])
            fine = self._refine(
                s["prefix"],
                s["origin"],
                coarse_end - timedelta(days=4),
                coarse_end + timedelta(days=1),
                f"withdrawal_{i}",
            )
            end = _ts(fine[-1]["end"]) if fine else coarse_end
            s = {**s, "end_refined": fine[-1]["end"] if fine else None}
            bp = self.stat(
                f"bgplay_withdrawal_{i}",
                "bgplay",
                resource=s["prefix"],
                starttime=_fmt(end - timedelta(hours=24)),
                endtime=_fmt(end + timedelta(hours=8)),
            )
            if bp:
                res["withdrawals"].append({**s, **withdrawal(bp)})
        # Chemins actuels et comparaison avec les autres préfixes de l'ASN
        st = self.stat("bgp_state_prefix", "bgp-state", resource=prefix)
        target_up = upstreams((r["path"] for r in (st or {}).get("bgp_state") or []), asn)
        res["upstreams_now"] = {
            "timestamp": (st or {}).get("timestamp"),
            "routes": sum(target_up.values()),
            "distribution": target_up.most_common(),
        }
        ap = self.stat("announced_prefixes_asn", "announced-prefixes", resource=f"AS{asn}")
        net = parse_network(prefix)
        candidates = sorted(
            (parse_network(p["prefix"]) for p in (ap or {}).get("prefixes") or []),
            key=lambda n: (n.prefixlen, str(n)),
        )
        refs = [n for n in candidates if n.version == net.version and not n.overlaps(net)]
        ref_up: Counter[int] = Counter()
        used: list[dict[str, Any]] = []
        for n in refs:
            if len(used) >= reference:
                break
            d = self.stat(f"bgp_state_reference_{len(used)}", "bgp-state", resource=str(n))
            c = upstreams((r["path"] for r in (d or {}).get("bgp_state") or []), asn)
            if c:
                used.append(
                    {"prefix": str(n), "routes": sum(c.values()), "distribution": c.most_common(8)}
                )
                ref_up.update(c)
        res["asn_prefix_count"] = len(candidates)
        res["reference"] = {
            "prefixes": used,
            "aggregate": ref_up.most_common(12),
            **compare_upstreams(target_up, ref_up),
        }
        return res

    def rpki(
        self, prefix: str, asn: int, covering: str, dates: list[str], tals: list[str]
    ) -> dict[str, Any]:
        res: dict[str, Any] = {}
        d = self.stat("rpki_validation", "rpki-validation", resource=asn, prefix=prefix)
        if d:
            res["validation_now"] = {
                "status": d.get("status"),
                "validator": d.get("validator"),
                "validating_roas": d.get("validating_roas"),
            }
        scope = parse_network(covering)
        archive: dict[str, Any] = {}
        for tal in tals:
            for day in dates:
                y, m, dd = day.split("-")
                url = ROA_ARCHIVE.format(tal=tal, y=y, m=m, d=dd)
                raw = self.fetch(url)
                sha = self.fetch(url + ".sha256")
                if raw is None:
                    continue
                expected = sha.decode().split()[0] if sha else None
                ok = expected == hashlib.sha256(raw).hexdigest()
                rows = filter_roas(lzma.decompress(raw).decode("utf-8"), scope)
                archive[f"{tal}/{day}"] = {
                    "url": url,
                    "sha256_file": expected,
                    "sha256_ok": ok,
                    "roas": rows,
                }
        if archive:
            self.save(
                "roa_archive",
                "Archives RPKI du RIPE NCC (ftp.ripe.net/rpki)",
                f"ROA recouvrant {covering}, dates {dates}",
                archive,
            )
        res["archive"] = {k: v["roas"] for k, v in archive.items()}
        res["archive_sha256_ok"] = all(v["sha256_ok"] for v in archive.values())
        return res

    def irr(
        self,
        prefix: str,
        covering: str,
        servers: Iterable[tuple[str, str, str]],
        max_maintainers: int = 5,
    ) -> dict[str, Any]:
        fam = "route6" if ":" in prefix else "route"
        res: dict[str, Any] = {"objects": {}, "maintainers": {}}
        mnts: set[tuple[str, str, str, str]] = set()
        for name, host, flags in servers:
            found = []
            for qname, q in (
                ("exact", f"-T {fam} -x {prefix}"),
                ("covering", f"-T {fam} -x {covering}"),
                ("more", f"-T {fam} -M {covering}"),
                ("less", f"-T {fam} -l {prefix}"),
            ):
                objs = self.whois(f"irr_{name}_{qname}", host, f"{flags} {q}".strip())
                for o in objs or []:
                    found.append(
                        {
                            "query": qname,
                            **{
                                k: o.get(k)
                                for k in (
                                    fam,
                                    "origin",
                                    "descr",
                                    "mnt-by",
                                    "source",
                                    "created",
                                    "last-modified",
                                    "changed",
                                )
                            },
                        }
                    )
                    for m in o.get("mnt-by") or []:
                        mnts.add((name, host, flags, m))
            res["objects"][name] = found
        for name, host, flags, m in sorted(mnts)[:max_maintainers]:
            objs = self.whois(f"irr_{name}_mnt_{m}", host, f"{flags} -i mnt-by {m}".strip()) or []
            mntner = self.whois(f"irr_{name}_mntner_{m}", host, f"{flags} -T mntner {m}".strip())
            months = Counter(
                (o.get("last-modified") or [""])[0][:7] for o in objs if o.get("last-modified")
            )
            res["maintainers"][f"{name}:{m}"] = {
                "objects": len(objs),
                "by_class": Counter(next(iter(o)) for o in objs).most_common(),
                "top_origins": Counter(
                    (o.get("origin") or ["?"])[0] for o in objs if o.get("origin")
                ).most_common(8),
                "last_modified_months": sorted(months.items())[-12:],
                "mntner": [
                    {
                        k: v
                        for k, v in o.items()
                        if k
                        in (
                            "mntner",
                            "descr",
                            "admin-c",
                            "created",
                            "last-modified",
                            "changed",
                            "source",
                        )
                    }
                    for o in mntner or []
                ],
            }
        return res

    def registry(self, prefix: str, asn: int, upstream_asns: list[int]) -> dict[str, Any]:
        res: dict[str, Any] = {}
        inet = self.whois("ripe_inetnum", "whois.ripe.net", f"-r -T inetnum {prefix}") or []
        inside = (
            self.whois("ripe_inetnum_more", "whois.ripe.net", f"-r -T inetnum -M {prefix}") or []
        )
        res["inetnum"] = inet
        res["inetnum_more_specific_count"] = len(inside)
        orgs = sorted({o for obj in inet for o in obj.get("org", [])})
        res["orgs"] = {}
        for org in orgs:
            objs = self.whois(f"ripe_org_{org}", "whois.ripe.net", f"-r {org}") or []
            res["orgs"][org] = [
                {
                    k: v
                    for k, v in o.items()
                    if k
                    in (
                        "organisation",
                        "org-name",
                        "org-type",
                        "country",
                        "created",
                        "last-modified",
                    )
                }
                for o in objs
            ]
        if inet:
            key = (inet[0].get("inetnum") or [""])[0]
            hw = self.stat("ripe_historical_inetnum", "historical-whois", resource=key)
            res["inetnum_history"] = [
                {"version": v.get("version"), "from": v.get("from_time"), "to": v.get("to_time")}
                for v in (hw or {}).get("versions") or []
            ]
        res["aut_num"] = {}
        for host, flags, label in (
            ("whois.radb.net", "-s RADB", "RADB"),
            ("whois.ripe.net", "-r", "RIPE"),
        ):
            objs = self.whois(f"autnum_AS{asn}_{label}", host, f"{flags} -T aut-num AS{asn}") or []
            res["aut_num"][label] = [
                {
                    "aut-num": o.get("aut-num"),
                    "as-name": o.get("as-name"),
                    "descr": o.get("descr"),
                    "org": o.get("org"),
                    "mnt-by": o.get("mnt-by"),
                    "last-modified": o.get("last-modified"),
                    "policy_lines": sum(
                        len(o.get(k, [])) for k in ("import", "export", "mp-import", "mp-export")
                    ),
                }
                for o in objs
            ]
        res["upstream_policies"] = {}
        for up in upstream_asns:
            objs = (
                self.whois(f"autnum_AS{up}_RIPE", "whois.ripe.net", f"-r -T aut-num AS{up}") or []
            )
            lines = [
                f"{k}: {v}"
                for o in objs
                for k in ("import", "export", "mp-import", "mp-export")
                for v in o.get(k, [])
                if re.search(rf"\bAS{asn}\b", v)
            ]
            res["upstream_policies"][f"AS{up}"] = {
                "found": bool(objs),
                "as-name": (objs[0].get("as-name") if objs else None),
                "org": (objs[0].get("org") if objs else None),
                "lines_mentioning_asn": lines,
                "first_version_mentioning_asn": self._first_mention(up, asn) if lines else None,
            }
        return res

    def _first_mention(self, holder: int, asn: int) -> dict[str, Any] | None:
        """Recherche par dichotomie dans `historical-whois` (suppose une mention continue)."""
        hw = self.stat(f"ripe_historical_AS{holder}", "historical-whois", resource=f"AS{holder}")
        versions = sorted((hw or {}).get("versions") or [], key=lambda v: v["version"])
        if not versions:
            return None

        def mentions(v: dict[str, Any]) -> bool:
            try:
                d = self.ripestat.get(
                    "historical-whois", resource=f"AS{holder}", version=v["version"]
                )
            except SourceError:
                return False
            attrs = ((d.get("objects") or [{}])[0]).get("attributes") or []
            return any(re.search(rf"\bAS{asn}\b", a.get("value", "")) for a in attrs)

        lo, hi = 0, len(versions) - 1
        if mentions(versions[lo]):
            return {
                "version": versions[lo]["version"],
                "from": versions[lo]["from_time"],
                "note": "présent dès la plus ancienne version disponible",
            }
        if not mentions(versions[hi]):
            return None
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if mentions(versions[mid]):
                hi = mid
            else:
                lo = mid
        return {
            "version": versions[hi]["version"],
            "from": versions[hi]["from_time"],
            "previous_version": versions[lo]["version"],
            "previous_from": versions[lo]["from_time"],
            "hypothèse": "mention supposée continue depuis cette version (dichotomie)",
        }

    def transfers(self, covering: str, holder_name: str | None) -> dict[str, Any]:
        raw = self.fetch(TRANSFERS_URL)
        if raw is None:
            return {}
        all_tr = json.loads(raw.decode("utf-8"))["transfers"]
        scope = parse_network(covering)
        hits = filter_transfers(all_tr, scope=scope)
        holder = filter_transfers(all_tr, org_name=holder_name) if holder_name else []
        self.save(
            "ripe_transfers",
            TRANSFERS_URL,
            f"transferts recouvrant {covering}"
            + (f" ou impliquant « {holder_name} »" if holder_name else ""),
            {"total_records": len(all_tr), "covering": hits, "holder": holder},
            note="Extrait filtré ; le fichier complet contient des noms de personnes "
            "physiques sans rapport et n'est pas conservé.",
        )
        return {"covering": hits, "holder": holder}

    def doh(self, name: str, rtype: str) -> dict[str, Any] | None:
        url = DOH_URL + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
        try:
            req = urllib.request.Request(
                url, headers={"accept": "application/dns-json", "User-Agent": USER_AGENT}
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                data: dict[str, Any] = json.loads(resp.read())
            return data
        except Exception as exc:  # noqa: BLE001
            self.fail(f"DoH {name} {rtype}", exc)
            return None

    def dns(self, prefix: str, covering: str, sample: int) -> dict[str, Any]:
        net = parse_network(prefix)
        if net.version != 4:
            return {"note": "DNS inverse IPv6 non collecté"}
        zones = sorted(
            {
                reverse_zone(parse_network(covering)),
                reverse_zone(net),
                *(reverse_zone(s) for s in list(net.subnets(new_prefix=24))[:1]),
            }
        )
        out: dict[str, Any] = {"ns": {}, "ptr": {}}
        for z in zones:
            d = self.doh(z, "NS")
            if d:
                out["ns"][z] = {
                    "status": d.get("Status"),
                    "answer": [a["data"] for a in d.get("Answer", [])],
                    "authority": [a["data"].split()[0] for a in d.get("Authority", [])],
                }
        for ip in ptr_sample(net, sample):
            name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            d = self.doh(name, "PTR")
            if d:
                out["ptr"][ip] = {
                    "status": d.get("Status"),
                    "answer": [a["data"] for a in d.get("Answer", [])],
                }
        self.save("dns_reverse", f"DNS-over-HTTPS {DOH_URL}", f"NS {zones} ; PTR échantillon", out)
        return out

    def provider_list(self, prefix: str, url: str, history: bool) -> dict[str, Any]:
        net = parse_network(prefix)
        body = self.fetch(url)
        res: dict[str, Any] = {"url": url}
        if body is not None:
            text = body.decode("utf-8", "replace")
            res["overlapping_entries"] = cidrs_overlapping(text, net)
            self.save(
                "provider_list",
                url,
                "liste publiée par l'opérateur",
                {"text": text[:200000], "overlapping_entries": res["overlapping_entries"]},
            )
        if history:
            cdx = self.fetch(
                WAYBACK_CDX
                + "?"
                + urllib.parse.urlencode(
                    {
                        "url": url.split("://", 1)[-1],
                        "output": "json",
                        "fl": "timestamp,statuscode,digest",
                        "collapse": "digest",
                    }
                )
            )
            snaps = []
            for row in (json.loads(cdx)[1:] if cdx else [])[-24:]:
                ts, code, digest = row
                if code != "200":
                    continue
                snap = self.fetch_retry(f"https://web.archive.org/web/{ts}id_/{url}")
                if snap is not None:
                    snaps.append(
                        {
                            "timestamp": ts,
                            "digest": digest,
                            "overlapping_entries": cidrs_overlapping(
                                snap.decode("utf-8", "replace"), net
                            ),
                        }
                    )
                time.sleep(3)
            res["wayback"] = snaps
            self.save("provider_list_wayback", WAYBACK_CDX, f"archives de {url}", snaps)
        return res

    def holder_scan(self, holder_org: str, exclude_prefix: str) -> dict[str, Any]:
        """Routes d'origine étrangère au titulaire, dans tout l'espace RIPE de `holder_org`."""
        inets = (
            self.whois(
                f"ripe_inetnum_org_{holder_org}",
                "whois.ripe.net",
                f"-r -T inetnum -i org {holder_org}",
            )
            or []
        )
        autnums = (
            self.whois(
                f"ripe_autnum_org_{holder_org}",
                "whois.ripe.net",
                f"-r -T aut-num -i org {holder_org}",
            )
            or []
        )
        own = {int(a["aut-num"][0][2:]) for a in autnums if a.get("aut-num")}
        blocks = []
        for o in inets:
            start, _, end = (o.get("inetnum") or ["-"])[0].partition("-")
            try:
                nets = ipaddress.summarize_address_range(
                    ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
                )
            except ValueError:
                continue
            blocks += [(str(n), (o.get("status") or [""])[0]) for n in nets]
        foreign: list[dict[str, Any]] = []
        for p, status in blocks:
            try:
                d = self.ripestat.get("routing-status", resource=p)
            except SourceError as exc:
                self.fail(f"routing-status {p}", exc)
                continue
            routes = [(p, int(o["origin"])) for o in d.get("origins") or []] + [
                (m["prefix"], int(m["origin"])) for m in d.get("more_specifics") or []
            ]
            foreign += [
                {"holder_block": p, "status": status, "prefix": q, "origin": a}
                for q, a in routes
                if a not in own and q != exclude_prefix
            ]
            time.sleep(self._pause)
        holders = {}
        for a, _ in Counter(f["origin"] for f in foreign).most_common():
            try:
                holders[a] = self.ripestat.get("as-overview", resource=f"AS{a}").get("holder")
            except SourceError:
                holders[a] = None
        res = {
            "holder_org": holder_org,
            "holder_asns": sorted(own),
            "blocks": len(blocks),
            "foreign_routes": foreign,
            "foreign_origin_holders": holders,
            "note": "Noms de détenteurs d'ASN à relire : ils peuvent désigner une personne "
            "physique et ne doivent alors pas être publiés.",
        }
        self.save(
            f"holder_scan_{holder_org}",
            "whois RIPE + RIPEstat routing-status/as-overview",
            f"espace de {holder_org}",
            res,
        )
        return res

    def transferred_blocks_routing(
        self, records: list[dict[str, Any]], holder_name: str
    ) -> list[dict[str, Any]]:
        out = []
        for t in records:
            src = str((t.get("source_organization") or {}).get("name") or "")
            if holder_name.lower() not in src.lower():
                continue
            for item in (t.get("ip4nets") or {}).get("transfer_set", []):
                for n in _range_networks(item):
                    try:
                        d = self.ripestat.get("routing-status", resource=str(n))
                    except SourceError as exc:
                        self.fail(f"routing-status {n}", exc)
                        continue
                    out.append(
                        {
                            "date": t.get("transfer_date"),
                            "recipient": (t.get("recipient_organization") or {}).get("name"),
                            "block": str(n),
                            "origins_exact": sorted(
                                {int(o["origin"]) for o in d.get("origins") or []}
                            ),
                            "more_specific_origins": sorted(
                                {int(m["origin"]) for m in d.get("more_specifics") or []}
                            ),
                            "more_specific_count": len(d.get("more_specifics") or []),
                        }
                    )
                    time.sleep(self._pause)
        self.save(
            "transferred_blocks_routing",
            "RIPEstat routing-status",
            f"blocs cédés par « {holder_name} »",
            out,
        )
        return out


def apply_redactions(
    out_dir: str | Path, terms: Iterable[str], keys: frozenset[str] = frozenset()
) -> int:
    """Masque des termes (insensible à la casse) dans `raw/`, puis recalcule empreintes et index.

    Sert à retirer un nom de personne physique repéré à la relecture, sans refaire la collecte.
    Retourne le nombre de fichiers modifiés.
    """
    out = Path(out_dir)
    patterns = [re.compile(re.escape(t), re.IGNORECASE) for t in terms if t]
    changed = 0
    index_path = out / "INDEX.json"
    index = json.loads(index_path.read_text("utf-8")) if index_path.exists() else []
    for path in sorted((out / "raw").glob("*.json")):
        record = json.loads(path.read_text("utf-8"))
        text = json.dumps(record["data"], ensure_ascii=False)
        new = json.dumps(mask_fields(record["data"], keys), ensure_ascii=False) if keys else text
        for pat in patterns:
            new = pat.sub("<masqué>", new)
        if new == text:
            continue
        record["data"] = json.loads(new)
        body = json.dumps(record["data"], ensure_ascii=False, sort_keys=True, default=str)
        record["meta"]["sha256_data"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        record["meta"]["note"] = (
            record["meta"].get("note", "") + " Termes masqués après "
            "relecture (données personnelles)."
        ).strip()
        path.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
        for entry in index:
            if entry["file"] == f"raw/{path.name}":
                entry.update(record["meta"])
        changed += 1
    for name in ("summary.json", "OBSERVATIONS.md"):
        f = out / name
        if f.exists():
            content = f.read_text("utf-8")
            for pat in patterns:
                content = pat.sub("<masqué>", content)
            f.write_text(content, encoding="utf-8")
    if index:
        index_path.write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    return changed


def default_roa_dates(first_seen: str | None, today: datetime) -> list[str]:
    days = {(today - timedelta(days=1)).date()}
    if first_seen:
        f = _ts(first_seen).date()
        days |= {f - timedelta(days=1), f + timedelta(days=1)}
    return sorted(d.isoformat() for d in days)


def collect(
    prefix: str,
    asn: int,
    out_dir: str | Path,
    ripestat: RipeStatClient,
    covering: str | None = None,
    roa_dates: list[str] | None = None,
    tals: list[str] | None = None,
    provider_list: str | None = None,
    provider_history: bool = False,
    reference: int = 6,
    ptr: int = 8,
    holder_org: str | None = None,
    holder_name: str | None = None,
    irr_servers: Iterable[tuple[str, str, str]] = DEFAULT_IRR,
    dossier: Dossier | None = None,
) -> dict[str, Any]:
    net = parse_network(prefix)
    cov = covering or str(net.supernet(new_prefix=max(8, net.prefixlen - 3)))
    d = dossier or Dossier(out_dir, ripestat)
    started = iso()
    summary: dict[str, Any] = {
        "prefix": str(net),
        "asn": asn,
        "covering": cov,
        "started_at": started,
        "tool": f"bgpmon {__version__}",
        "method": "Collecte 100 % passive : API et fichiers publics uniquement, aucun scan.",
    }
    summary["routing"] = d.routing(str(net), asn, cov, reference)
    routing = summary["routing"]
    first = routing.get("first_seen_refined") or (routing.get("target_spans") or [{}])[0].get(
        "start"
    )
    dates = roa_dates or default_roa_dates(first, utcnow())
    summary["rpki"] = d.rpki(str(net), asn, cov, dates, tals or ["ripencc"])
    summary["irr"] = d.irr(str(net), cov, irr_servers)
    app = summary["routing"].get("appearance") or {}
    first_hour = (app.get("hourly_upstreams") or [{}])[0].get("upstreams") or []
    ups = [int(a) for a, _ in first_hour[:3]]
    summary["registry"] = d.registry(str(net), asn, ups)
    summary["transfers"] = d.transfers(cov, holder_name)
    summary["dns"] = d.dns(str(net), cov, ptr)
    if provider_list:
        summary["provider_list"] = d.provider_list(str(net), provider_list, provider_history)
    if holder_org:
        summary["holder_scan"] = d.holder_scan(holder_org, str(net))
    if holder_name and summary["transfers"].get("holder"):
        summary["transferred_blocks"] = d.transferred_blocks_routing(
            summary["transfers"]["holder"], holder_name
        )
    summary["finished_at"] = iso()
    summary["unverified"] = d.unverified
    out = Path(out_dir)
    (out / "summary.json").write_text(
        json.dumps(redact(summary), ensure_ascii=False, indent=1, default=str), encoding="utf-8"
    )
    (out / "INDEX.json").write_text(
        json.dumps(d.index, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    (out / "OBSERVATIONS.md").write_text(render_observations(summary), encoding="utf-8")
    return summary


# ── Rendu des constats (sans interprétation) ──────────────────────────────


def _asl(items: Iterable[Any]) -> str:
    return ", ".join(f"AS{a} ({n})" for a, n in items) or "—"


def render_observations(s: dict[str, Any]) -> str:
    r = s.get("routing", {})
    lines = [
        f"# Constats bruts — {s['prefix']} / AS{s['asn']}",
        "",
        f"Généré par {s['tool']} entre {s['started_at']} et {s.get('finished_at', '—')} (UTC).",
        "Ce fichier liste des observations datées, sans interprétation. Chaque ligne "
        "renvoie à un fichier de `raw/` (voir `INDEX.json`).",
        "",
        "## Routage",
        "",
        "| Origine | Préfixe | Début | Fin | Peers RIS (max) |",
        "|---|---|---|---|---|",
    ]
    for sp in r.get("history_400d") or r.get("history_full") or []:
        lines.append(
            f"| AS{sp['origin']} | {sp['prefix']} | {sp['start']} | {sp['end']} | "
            f"{sp['max_peers']:.0f} |"
        )
    app = r.get("appearance") or {}
    lines += [
        "",
        f"- Première période fine (routing-history) : {r.get('first_seen_refined') or '—'}",
        f"- Première annonce observée (BGPlay) : {app.get('first_announcement', '—')}, "
        f"chemin `{' '.join(map(str, app.get('first_path') or [])) or '—'}`.",
    ]
    for h in app.get("hourly_upstreams") or []:
        lines.append(
            f"  - {h['hour']}h : {h['announcements']} annonces, upstreams {_asl(h['upstreams'])}"
        )
    for w in r.get("withdrawals") or []:
        lines.append(
            f"- Retrait AS{w['origin']} {w['prefix']} (fin fine {w.get('end_refined') or '—'}) : "
            f"premier {w['first_withdrawal']}, "
            f"dernier {w['last_withdrawal']}, peers restants "
            f"{w['peers_still_announcing_at_window_end']}/{w['initial_peers']}."
        )
    up = r.get("upstreams_now") or {}
    ref = r.get("reference") or {}
    absent = [
        (x["asn"], x["reference_routes"])
        for x in ref.get("reference_upstreams_absent_from_target", [])[:6]
    ]
    rpki_now = (s.get("rpki", {}).get("validation_now") or {}).get("status", "—")
    lines += [
        f"- Upstreams actuels ({up.get('timestamp')}, {up.get('routes')} routes) : "
        f"{_asl(up.get('distribution', [])[:8])}",
        f"- Référence ({len(ref.get('prefixes', []))} autres préfixes de l'ASN) : "
        f"{_asl(ref.get('aggregate', [])[:8])}",
        f"- Part des routes passant par un upstream habituel : "
        f"{ref.get('share_of_target_routes_via_reference_upstreams_pct', '—')} %",
        f"- Upstreams habituels absents : {_asl(absent)}",
        "",
        "## RPKI",
        "",
        f"- Validation actuelle : {rpki_now}",
        f"- Archives vérifiées (SHA-256) : {s.get('rpki', {}).get('archive_sha256_ok')}",
    ]
    for day, roas in (s.get("rpki", {}).get("archive") or {}).items():
        sel = [
            f"{x['prefix']} {x['asn']} max {x['max_length']}"
            for x in roas
            if parse_network(x["prefix"]).overlaps(parse_network(s["prefix"]))
        ]
        lines.append(f"- {day} : {', '.join(sel) or 'aucune ROA recouvrant le préfixe'}")
    lines += ["", "## IRR", ""]
    for srv, objs in (s.get("irr", {}).get("objects") or {}).items():
        for o in objs:
            lines.append(
                f"- {srv} ({o['query']}) : {(o.get('route') or o.get('route6') or ['?'])[0]} "
                f"origine {(o.get('origin') or ['?'])[0]}, "
                f"mnt-by {', '.join(o.get('mnt-by') or [])}, "
                f"last-modified {(o.get('last-modified') or ['—'])[0]}"
            )
    for m, ctx in (s.get("irr", {}).get("maintainers") or {}).items():
        lines.append(
            f"- Maintainer {m} : {ctx['objects']} objets, origines principales "
            f"{ctx['top_origins'][:4]}"
        )
    reg = s.get("registry", {})
    lines += ["", "## Registre", ""]
    for o in reg.get("inetnum") or []:
        lines.append(
            f"- inetnum {(o.get('inetnum') or ['?'])[0]} : {(o.get('netname') or ['?'])[0]}, "
            f"{(o.get('status') or ['?'])[0]}, org {', '.join(o.get('org') or [])}, "
            f"created {(o.get('created') or ['—'])[0]}"
        )
    for asn_, pol in (reg.get("upstream_policies") or {}).items():
        lines.append(
            f"- Politique {asn_} mentionnant AS{s['asn']} : {pol['lines_mentioning_asn'][:4]} "
            f"; première version : {pol.get('first_version_mentioning_asn')}"
        )
    lines += ["", "## Transferts RIPE NCC", ""]
    for t in (s.get("transfers") or {}).get("covering") or []:
        lines.append(
            f"- {t.get('transfer_date')} {t.get('type')} : "
            f"{(t.get('source_organization') or {}).get('name')} → "
            f"{(t.get('recipient_organization') or {}).get('name')}, "
            f"{(t.get('ip4nets') or {}).get('transfer_set')}"
        )
    dns = s.get("dns", {})
    lines += ["", "## DNS inverse", ""]
    for z, v in (dns.get("ns") or {}).items():
        lines.append(f"- NS {z} : statut {v['status']}, {v['answer'] or v['authority']}")
    if s.get("provider_list"):
        pl = s["provider_list"]
        lines += [
            "",
            "## Liste publiée par l'opérateur",
            "",
            f"- {pl['url']} : entrées recouvrant le préfixe {pl.get('overlapping_entries')}",
        ]
        for w in pl.get("wayback") or []:
            lines.append(f"  - archive {w['timestamp']} : {w['overlapping_entries'] or 'aucune'}")
    lines += ["", "## Non vérifié", ""] + [f"- {u}" for u in s.get("unverified") or ["—"]]
    return "\n".join(lines) + "\n"
