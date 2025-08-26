#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tor-based .onion crawler with IOC extraction + keyword filters + MISP/STIX exporters.
"""

import argparse, time, random, re, csv, json, sys, queue, hashlib, uuid
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests
from requests.exceptions import RequestException
import tldextract
from datetime import datetime, timezone

# Optional: circuit rotation (Tor ControlPort)
try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except Exception:
    STEM_AVAILABLE = False

# Optional exporters
try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
    PYMISP_AVAILABLE = True
except Exception:
    PYMISP_AVAILABLE = False

try:
    import stix2
    STIX_AVAILABLE = True
except Exception:
    STIX_AVAILABLE = False

USER_AGENT = "OnionOSINT/1.1 (+local)"
DEFAULT_SOCKS = "socks5h://127.0.0.1:9050"
NOW_ISO = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

IOC_REGEX = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(r"\b(?:[a-z0-9][a-z0-9\-]{0,62}\.)+[a-z]{2,24}\b", re.I),
    "url": re.compile(r"\bhttps?://[^\s\"'>)]+", re.I),
    "email": re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    # BTC legacy/P2SH + bech32
    "btc": re.compile(r"\b(bc1[0-9a-z]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    # onion v3 hostnames
    "onion": re.compile(r"\b[a-z2-7]{56}\.onion\b", re.I),
}

RANSOM_KEYWORDS = [
    "ransom", "victim", "leak site", "data leak", "steal", "breach",
    "decryptor", "locker", "payload", "exfiltrate", "double extortion",
    "credentials", "vpn", "rdp", "initial access broker", "IAB", "access for sale"
]

def normalize_domain(d):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d):
        return None
    return d.lower()

def extract_iocs(text):
    found = {}
    for k, rgx in IOC_REGEX.items():
        vals = set(m.group(0) for m in rgx.finditer(text or ""))
        if k == "domain":
            vals = {v for v in (normalize_domain(x) for x in vals) if v}
        if vals:
            found[k] = sorted(vals)
    return found

def text_hits_keywords(text, keywords):
    if not keywords:
        return True
    t = (text or "").lower()
    for kw in keywords:
        if kw.lower() in t:
            return True
    return False

def build_session(socks_url):
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    s.proxies.update({"http": socks_url, "https": socks_url})
    return s

def same_host(u1, u2):
    return urlparse(u1).netloc.lower() == urlparse(u2).netloc.lower()

def is_onion_url(u):
    try:
        return urlparse(u).hostname and urlparse(u).hostname.endswith(".onion")
    except Exception:
        return False

def get_robots(session, base):
    robots_url = urljoin(base, "/robots.txt")
    try:
        r = session.get(robots_url, timeout=25)
        if r.status_code != 200 or len(r.text) > 200_000:
            return None
        return parse_robots(r.text)
    except RequestException:
        return None

def parse_robots(text):
    disallow = []
    ua = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(":", 1)]
        if len(parts) != 2:
            continue
        k, v = parts[0].lower(), parts[1]
        if k == "user-agent":
            ua = v
        elif k == "disallow" and (ua == "*" or ua is None):
            rule = v if v.startswith("/") else ("/" + v if v else "/")
            disallow.append(rule)
    return disallow or None

def allowed_by_robots(disallow_rules, path):
    if not disallow_rules:
        return True
    for rule in disallow_rules:
        if path.startswith(rule):
            return False
    return True

def rotate_circuit(ctrl_port, ctrl_password):
    if not STEM_AVAILABLE:
        return False
    try:
        with Controller.from_port(port=ctrl_port) as c:
            c.authenticate(password=ctrl_password)
            c.signal(Signal.NEWNYM)
        return True
    except Exception:
        return False

def sha1(s):  # small helper for stable IDs
    return hashlib.sha1(s.encode()).hexdigest()

def export_to_misp(misp_url, misp_key, misp_verify, orgc, event_info, tlp, attributes):
    if not PYMISP_AVAILABLE:
        print("[warn] PyMISP not installed; skipping MISP export")
        return
    misp = PyMISP(misp_url, misp_key, misp_verify, debug=False)
    ev = MISPEvent()
    ev.info = event_info
    ev.distribution = 0  # Your org only (change per policy)
    ev.threat_level_id = 2
    ev.analysis = 0
    ev.add_tag(f"TLP:{tlp}")
    ev.date = datetime.utcnow().date().isoformat()
    ev.orgc = orgc or "OSINT"
    for a in attributes:
        attr = MISPAttribute()
        attr.type = a["misp_type"]
        attr.value = a["value"]
        attr.comment = a.get("comment", "")
        attr.to_ids = True
        if "category" in a:
            attr.category = a["category"]
        ev.add_attribute(**attr)
    result = misp.add_event(ev)
    if isinstance(result, dict) and result.get("Event"):
        print(f"[MISP] Event created: {result['Event'].get('id')}")
    else:
        print("[MISP] Event create result:", result)

def export_to_stix(stix_path, source_name, objects):
    if not STIX_AVAILABLE:
        print("[warn] stix2 not installed; skipping STIX export")
        return
    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    with open(stix_path, "w", encoding="utf-8") as f:
        f.write(str(bundle))
    print(f"[STIX] Bundle written: {stix_path}")

def stix_objects_from_iocs(iocs_rows, source_name):
    if not STIX_AVAILABLE:
        return []
    objs = []
    sdo_map = {}  # value+type -> id
    def ensure_indicator(v, t):
        key = f"{t}:{v}"
        if key in sdo_map:
            return sdo_map[key]
        # map types
        if t == "domain":
            ind = stix2.Indicator(name=v, pattern=f"[domain-name:value = '{v}']",
                                  pattern_type="stix", created=NOW_ISO, modified=NOW_ISO)
        elif t == "url":
            ind = stix2.Indicator(name=v, pattern=f"[url:value = '{v}']",
                                  pattern_type="stix", created=NOW_ISO, modified=NOW_ISO)
        elif t == "ipv4":
            ind = stix2.Indicator(name=v, pattern=f"[ipv4-addr:value = '{v}']",
                                  pattern_type="stix", created=NOW_ISO, modified=NOW_ISO)
        elif t in ("sha256","sha1","md5"):
            algo = t.upper()
            ind = stix2.Indicator(
                name=v,
                pattern=f"[file:hashes.'{algo}' = '{v.lower()}']",
                pattern_type="stix", created=NOW_ISO, modified=NOW_ISO
            )
        elif t == "btc":
            # custom object for wallet
            ind = stix2.CustomObject(
                'x-crypto-wallet',
                [
                    ('value', stix2.properties.StringProperty(required=True)),
                    ('currency', stix2.properties.StringProperty(required=True)),
                    ('labels', stix2.properties.ListProperty(stix2.properties.StringProperty)),
                    ('created', stix2.properties.TimestampProperty()),
                    ('modified', stix2.properties.TimestampProperty())
                ]
            )(value=v, currency="BTC", labels=["k:wallet", source_name], created=NOW_ISO, modified=NOW_ISO)
        else:
            return None
        sdo_map[key] = ind
        objs.append(ind)
        return ind
    for row in iocs_rows:
        v, t, src, preview = row
        ind = ensure_indicator(v, t)
        if not ind:
            continue
        # note object with context
        note = stix2.Note(
            content=f"Seen on {src}\n\nPreview: {preview[:200]}",
            created=NOW_ISO, modified=NOW_ISO,
            object_refs=[ind.id], labels=[source_name, "osint", "tor"]
        )
        objs.append(note)
    return objs

def choose_misp_type(ioc_type, value):
    mapping = {
        "domain": ("domain", "Network activity"),
        "url": ("url", "Network activity"),
        "ipv4": ("ip-dst", "Network activity"),
        "email": ("email-src", "Payload delivery"),
        "sha256": ("sha256", "Artifacts dropped"),
        "sha1": ("sha1", "Artifacts dropped"),
        "md5": ("md5", "Artifacts dropped"),
        "btc": ("btc", "Financial fraud")  # custom type often named 'btc' in some MISP dist; else use 'other'
    }
    if ioc_type in mapping:
        mt, cat = mapping[ioc_type]
        return {"misp_type": mt, "category": cat, "value": value}
    # fallback
    return {"misp_type": "other", "category": "External analysis", "value": f"{ioc_type}:{value}"}

def crawl(args):
    session = build_session(args.socks)
    seeds = [u.strip() for u in args.seeds if u.strip()]
    frontier = queue.Queue()
    for s in seeds:
        frontier.put((s, 0))

    seen_pages = set()
    host_meta = {}  # host -> {'count':int or 'robots':list}
    iocs_global = set()

    pages_out = open(args.pages_out, "w", encoding="utf-8")
    iocs_csv = open(args.iocs_out, "w", newline="", encoding="utf-8")
    ioc_writer = csv.writer(iocs_csv)
    ioc_writer.writerow(["indicator", "type", "source_url", "context_preview"])

    processed = 0
    start = time.time()

    # Prepare keyword lists
    kw_include = [k.strip() for k in args.keyword if k.strip()] if args.keyword else []
    kw_ransom = RANSOM_KEYWORDS if args.focus_ransom else []
    allow_hosts = set(h.lower() for h in (args.allow_host or []))
    deny_hosts = set(h.lower() for h in (args.deny_host or []))

    while not frontier.empty() and processed < args.max_pages:
        url, depth = frontier.get()
        if url in seen_pages:
            continue
        if not is_onion_url(url):
            continue
        seen_pages.add(url)

        host = urlparse(url).netloc.lower()
        if allow_hosts and host not in allow_hosts:
            continue
        if host in deny_hosts:
            continue

        meta = host_meta.get(host, {"count": 0, "robots": None})
        if isinstance(meta.get("count"), int) and meta["count"] >= args.max_per_host:
            continue

        if meta["robots"] is None:
            meta["robots"] = get_robots(session, f"http://{host}")
        host_meta[host] = meta

        path = urlparse(url).path or "/"
        if meta["robots"] and not allowed_by_robots(meta["robots"], path):
            continue

        # politeness
        time.sleep(args.delay + random.uniform(0, args.delay * 0.5))

        # Optional circuit rotation
        if args.rotate_every and processed and processed % args.rotate_every == 0 and args.ctrl_port and args.ctrl_password:
            rotate_circuit(args.ctrl_port, args.ctrl_password)

        # fetch
        status, html, title, links = None, "", "", []
        try:
            r = session.get(url, allow_redirects=True, timeout=45)
            status = r.status_code
            ct = r.headers.get("content-type", "").lower()
            if ct.startswith("text/") and len(r.content) <= args.max_bytes:
                html = r.text
        except RequestException as e:
            status = f"ERR:{type(e).__name__}"

        if html:
            soup = BeautifulSoup(html, "html.parser")
            t = soup.find("title")
            title = (t.text or "").strip()[:200] if t else ""
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith("#") or href.lower().startswith("javascript:"):
                    continue
                nxt = urljoin(url, href)
                if not args.allow_external and not is_onion_url(nxt):
                    continue
                if args.same_host_only and not same_host(url, nxt):
                    continue
                links.append(nxt)

        # Keyword gating (only write IOCs if text matches)
        gate_ok = text_hits_keywords(html, kw_include) and text_hits_keywords(html, kw_ransom)

        # Extract IOCs
        if html and gate_ok:
            found = extract_iocs(html)
            # Heuristic: if focusing ransomware, prefer rows from pages that include ransom-y terms
            for t, vals in found.items():
                for v in vals:
                    key = (v, t)
                    if key in iocs_global:
                        continue
                    iocs_global.add(key)
                    preview = (html[:160].replace("\n", " ") if html else "")
                    ioc_writer.writerow([v, t, url, preview])

        # record page metadata
        rec = {"url": url, "status": status, "title": title, "depth": depth, "links_found": len(links)}
        pages_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
        processed += 1

        # per-host count
        if isinstance(meta.get("count"), int):
            meta["count"] += 1
        host_meta[host] = meta

        if depth < args.max_depth:
            random.shuffle(links)
            for nxt in links:
                if nxt not in seen_pages:
                    frontier.put((nxt, depth + 1))

    pages_out.close()
    iocs_csv.close()

    # Build export payloads if requested
    if args.export_misp or args.export_stix:
        # read back CSV (skipping header)
        rows = []
        with open(args.iocs_out, newline="", encoding="utf-8") as f:
            rdr = csv.reader(f)
            next(rdr, None)
            for r in rdr:
                # normalize types to our mapping keys
                typ = r[1].lower()
                if typ == "ipv4":
                    typ = "ipv4"
                rows.append((r[0], typ, r[2], r[3]))

        if args.export_misp:
            attrs = []
            for v, t, src, prev in rows:
                m = choose_misp_type(t, v)
                m["comment"] = f"OSINT (Tor). Source: {src}"
                attrs.append(m)
            export_to_misp(args.misp_url, args.misp_key, not args.misp_insecure,
                           args.misp_orgc, args.misp_info or "Dark-web OSINT IOCs",
                           args.misp_tlp, attrs)

        if args.export_stix:
            objs = stix_objects_from_iocs(rows, args.stix_source or "darkweb-osint")
            export_to_stix(args.stix_path, args.stix_source or "darkweb-osint", objs)

    print(f"[done] pages={processed} seeds={len(seeds)} unique_iocs={len(iocs_global)} elapsed={int(time.time()-start)}s")
    print(f"Pages JSONL: {args.pages_out}")
    print(f"IOCs CSV:    {args.iocs_out}")

def main():
    ap = argparse.ArgumentParser(description="Tor .onion crawler with IOC extraction + MISP/STIX export")
    ap.add_argument("--seeds", nargs="+", required=True, help="Seed .onion URLs")
    ap.add_argument("--socks", default=DEFAULT_SOCKS, help="SOCKS (Tor) e.g. socks5h://127.0.0.1:9050")
    ap.add_argument("--max-pages", type=int, default=120)
    ap.add_argument("--max-per-host", type=int, default=25)
    ap.add_argument("--max-depth", type=int, default=2)
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--max-bytes", type=int, default=2_000_000)
    ap.add_argument("--same-host-only", action="store_true")
    ap.add_argument("--allow-external", action="store_true")
    ap.add_argument("--rotate-every", type=int, default=0)
    ap.add_argument("--ctrl-port", type=int, default=9051)
    ap.add_argument("--ctrl-password", default="")
    ap.add_argument("--pages-out", default="pages.jsonl")
    ap.add_argument("--iocs-out", default="iocs.csv")

    # Filtering
    ap.add_argument("--keyword", nargs="*", help="Only keep IOCs if page contains ANY of these keywords (case-insensitive)")
    ap.add_argument("--focus-ransom", action="store_true", help="Also require ransomware-related keywords")
    ap.add_argument("--allow-host", nargs="*", help="Only crawl these onion hosts (netlocs)")
    ap.add_argument("--deny-host", nargs="*", help="Skip these onion hosts (netlocs)")

    # MISP export
    ap.add_argument("--export-misp", action="store_true")
    ap.add_argument("--misp-url")
    ap.add_argument("--misp-key")
    ap.add_argument("--misp-insecure", action="store_true", help="Disable TLS verify")
    ap.add_argument("--misp-orgc", default="OSINT")
    ap.add_argument("--misp-info", default="Dark-web OSINT IOCs")
    ap.add_argument("--misp-tlp", default="AMBER")

    # STIX export
    ap.add_argument("--export-stix", action="store_true")
    ap.add_argument("--stix-path", default="osint_bundle.json")
    ap.add_argument("--stix-source", default="darkweb-osint")

    args = ap.parse_args()
    crawl(args)

if __name__ == "__main__":
    main()

1) Focus on your brand & creds
python3 onion_crawler_osint.py \
  --seeds "http://<seed1>.onion/" "http://<seed2>.onion/" \
  --same-host-only \
  --max-pages 100 --max-per-host 20 --max-depth 2 --delay 3 \
  --keyword yourcompany.com yourproduct "vpn" "credentials" "leak"

2)Track ransomware posts + BTC wallets (with STIX)
python3 onion_crawler_osint.py \
  --seeds "http://<ransom-blog>.onion/" \
  --focus-ransom \
  --max-pages 60 --max-depth 1 \
  --export-stix --stix-path osint_bundle.json

Push straight to MISP
python3 onion_crawler_osint.py \
  --seeds "http://<seed>.onion/" \
  --keyword yourcompany.com \
  --export-misp \
  --misp-url https://misp.example.tld \
  --misp-key <API_KEY> \
  --misp-info "Dark-web OSINT IOCs (weekly sweep)" \
  --misp-tlp AMBER
