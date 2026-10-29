# ThreatLens backend (Python / FastAPI)
# Aggregates threat intelligence from VirusTotal, AbuseIPDB, Shodan InternetDB, RDAP and ip-api.com
# The browser can't call these APIs directly (CORS + secret keys), so this server acts as a secure proxy.
# Every report is stored in SQLite: it powers the history dashboard and a 1-hour cache that saves API quota.

import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import sqlite3
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from email_analyzer import analyze_email
from heuristics import abuse_category_counts, mitre_mapping, phishing_analysis

load_dotenv()


def env_key(name):
    # Treat the .env.example placeholders as "not configured"
    value = (os.getenv(name) or "").strip()
    return None if not value or value.startswith("paste_") else value


PORT = int(os.getenv("PORT", "5000"))
VT_KEY = env_key("VT_API_KEY")
ABUSE_KEY = env_key("ABUSEIPDB_API_KEY")
CACHE_TTL = timedelta(hours=1)
DB_PATH = Path(__file__).with_name("threatlens.db")

app = FastAPI(title="ThreatLens")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])

HASH_RE = re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)  # MD5 / SHA-1 / SHA-256
URL_RE = re.compile(r"^https?://", re.I)
DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def now():
    return datetime.now(timezone.utc)


# ---------- 0. Storage (SQLite: history + cache) ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


with db() as conn:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS lookups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            type TEXT NOT NULL,
            level TEXT NOT NULL,
            score INTEGER,
            complete INTEGER NOT NULL,
            report TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_lookups_query ON lookups(query, created_at)")


def save_report(report, complete):
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO lookups (query, type, level, score, complete, report, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (report["query"], report["type"], report["risk"]["level"], report["risk"]["score"],
             int(complete), json.dumps(report), report["checkedAt"]),
        )
        return cur.lastrowid


def cached_report(query):
    since = (now() - CACHE_TTL).isoformat()
    with db() as conn:
        row = conn.execute(
            "SELECT id, report FROM lookups WHERE query = ? AND complete = 1 AND created_at >= ? ORDER BY id DESC LIMIT 1",
            (query, since),
        ).fetchone()
    if not row:
        return None
    return {**json.loads(row["report"]), "id": row["id"], "cached": True}


# ---------- 0b. Offline demo mode ----------
# Every successful live API response is recorded as a "fixture". With demo mode on, sources are answered from
# those fixtures instead of the network, so a presentation still works when the venue Wi-Fi does not.
with db() as conn:
    conn.execute("CREATE TABLE IF NOT EXISTS fixtures (key TEXT PRIMARY KEY, data TEXT NOT NULL, saved_at TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")


def get_setting(key, default=None):
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


def set_setting(key, value):
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, json.dumps(value)))


def demo_mode():
    return bool(get_setting("demo_mode", False))


def load_fixture(key, max_age=None):
    with db() as conn:
        row = conn.execute("SELECT data, saved_at FROM fixtures WHERE key = ?", (key,)).fetchone()
    if not row:
        return None
    if max_age and now() - datetime.fromisoformat(row["saved_at"]) > max_age:
        return None
    return json.loads(row["data"])


def save_fixture(key, data):
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO fixtures (key, data, saved_at) VALUES (?, ?, ?)", (key, json.dumps(data), now().isoformat()))


async def source(key, factory):
    """Run one intelligence source: replayed from a fixture in demo mode, otherwise live (and recorded)."""
    if demo_mode():
        hit = load_fixture(key)
        return hit if hit is not None else {"error": "Not recorded yet: scan this indicator once while online to use it in offline demo mode"}
    result = await safe(factory())
    if isinstance(result, dict) and not result.get("error"):
        save_fixture(key, result)
    return result


async def resolve(host):
    if demo_mode():
        return (load_fixture(f"dns:{host}") or {}).get("ip")
    ip = await resolve_ip(host)
    if ip:
        save_fixture(f"dns:{host}", {"ip": ip})
    return ip


# ---------- 1. Indicator type detection ----------
def is_ip(q):
    try:
        ipaddress.ip_address(q)
        return True
    except ValueError:
        return False


def detect_type(q):
    if is_ip(q):
        return "ip"
    if HASH_RE.match(q):
        return "hash"
    if URL_RE.match(q):
        return "url"
    if DOMAIN_RE.match(q):
        return "domain"
    return None


def refang(text):
    # Undo common "defanging" used in threat reports: hxxp://evil[.]com -> http://evil.com
    text = re.sub(r"\bhxxp(s?)", r"http\1", text, flags=re.I)
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", text, flags=re.I)
    text = re.sub(r"\[:\]|\[://\]", lambda m: m.group(0)[1:-1], text)
    return text


async def resolve_ip(host):
    if not host:
        return None
    if is_ip(host):
        return host
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, family=socket.AF_INET)
        return infos[0][4][0]
    except Exception:
        return None


def registrable_domain(host):
    # Good-enough eTLD+1 guess for RDAP: keeps "example.co.uk", trims "www.mail.example.com"
    parts = host.lower().split(".")
    if len(parts) > 2 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# Runs a lookup and turns any crash into an error object, so one failing source never breaks the report
async def safe(coro):
    try:
        return await coro
    except httpx.TimeoutException:
        return {"error": "Request timed out"}
    except Exception as err:
        return {"error": str(err) or "Request failed"}


async def none():
    return None


# ---------- 2. VirusTotal ----------
def vt_details(type_, a):
    d = []

    def add(label, value):
        if value is not None and value != "":
            d.append({"label": label, "value": str(value)})

    def date(s):
        return datetime.fromtimestamp(s, timezone.utc).strftime("%Y-%m-%d") if s else None

    if type_ == "ip":
        add("AS owner", a.get("as_owner"))
        add("ASN", a.get("asn"))
        add("Network", a.get("network"))
        add("Country", a.get("country"))
    if type_ == "domain":
        add("Registrar", a.get("registrar"))
        add("Created", date(a.get("creation_date")))
        add("Categories", ", ".join(list((a.get("categories") or {}).values())[:3]))
    if type_ == "hash":
        size = a.get("size")
        add("File name", a.get("meaningful_name"))
        add("File type", a.get("type_description"))
        add("Size", f"{size / 1024:.1f} KB" if size else None)
        add("First seen", date(a.get("first_submission_date")))
        add("SHA-256", a.get("sha256"))
    if type_ == "url":
        add("Page title", a.get("title"))
        add("Final URL", a.get("last_final_url"))
        add("HTTP status", a.get("last_http_response_code"))
    add("Tags", ", ".join((a.get("tags") or [])[:5]))
    add("Last analysed", date(a.get("last_analysis_date")))
    return d


def vt_threat_label(a):
    # Popular malware family / threat name, e.g. "trojan.emotet/heodo"
    label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label")
    return label or None


async def virus_total(client, type_, q):
    if not VT_KEY:
        return {"error": "VirusTotal API key is missing in server/.env"}

    # VT URL id = unpadded base64url of the URL
    url_id = base64.urlsafe_b64encode(q.encode()).decode().rstrip("=")
    paths = {
        "ip": f"ip_addresses/{q}",
        "domain": f"domains/{q}",
        "hash": f"files/{q}",
        "url": f"urls/{url_id}",
    }

    res = await client.get(
        f"https://www.virustotal.com/api/v3/{paths[type_]}",
        headers={"x-apikey": VT_KEY},
        timeout=10,
    )
    if res.status_code == 404:
        return {"notFound": True}
    if res.status_code == 429:
        return {"error": "VirusTotal rate limit hit (free plan: 4 lookups/min). Wait a minute.", "rateLimited": True}
    if res.status_code == 401:
        return {"error": "VirusTotal rejected the API key (401). Check VT_API_KEY in server/.env"}
    if not res.is_success:
        return {"error": f"VirusTotal returned {res.status_code}"}

    a = res.json()["data"]["attributes"]
    detections = [
        {"engine": r.get("engine_name"), "category": r["category"], "result": r.get("result") or r["category"]}
        for r in (a.get("last_analysis_results") or {}).values()
        if r.get("category") in ("malicious", "suspicious")
    ]
    return {
        "stats": a.get("last_analysis_stats") or {},
        "reputation": a.get("reputation"),
        "threatLabel": vt_threat_label(a),
        "detections": detections,
        "details": vt_details(type_, a),
        "link": f"https://www.virustotal.com/gui/{VT_GUI_PATH[type_]}/{url_id if type_ == 'url' else q}",
    }


VT_GUI_PATH = {"ip": "ip-address", "domain": "domain", "hash": "file", "url": "url"}


# ---------- 3. AbuseIPDB ----------
async def abuse_ipdb(client, ip):
    if not ABUSE_KEY:
        return {"error": "AbuseIPDB API key is missing in server/.env"}

    res = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
        headers={"Key": ABUSE_KEY, "Accept": "application/json"},
        timeout=10,
    )
    if res.status_code == 401:
        return {"error": "AbuseIPDB rejected the API key (401). Check ABUSEIPDB_API_KEY in server/.env"}
    if res.status_code == 429:
        return {"error": "AbuseIPDB daily limit reached (free plan: 1,000 checks/day)."}
    if not res.is_success:
        return {"error": f"AbuseIPDB returned {res.status_code}"}

    data = res.json()["data"]
    return {
        "score": data.get("abuseConfidenceScore"),
        "totalReports": data.get("totalReports"),
        "distinctUsers": data.get("numDistinctUsers"),
        "isp": data.get("isp"),
        "usageType": data.get("usageType"),
        "domain": data.get("domain"),
        "isTor": data.get("isTor"),
        "isWhitelisted": data.get("isWhitelisted"),
        "lastReportedAt": data.get("lastReportedAt"),
        "categories": abuse_category_counts(data.get("reports")),
    }


# ---------- 4. Shodan InternetDB (free, no key): open ports + known CVEs ----------
async def shodan_internetdb(client, ip):
    res = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
    if res.status_code == 404:
        return {"notFound": True}
    if not res.is_success:
        return {"error": f"Shodan InternetDB returned {res.status_code}"}
    d = res.json()
    return {
        "ports": sorted(d.get("ports") or []),
        "vulns": sorted(d.get("vulns") or [], reverse=True),
        "hostnames": d.get("hostnames") or [],
        "tags": d.get("tags") or [],
        "cpes": d.get("cpes") or [],
    }


# ---------- 5. RDAP / WHOIS (free, no key): domain age & registrar ----------
async def rdap(client, domain):
    res = await client.get(f"https://rdap.org/domain/{domain}", timeout=10, follow_redirects=True)
    if res.status_code == 404:
        return {"notFound": True}
    if not res.is_success:
        return {"error": f"RDAP returned {res.status_code}"}
    d = res.json()

    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events") or []}
    registrar = None
    for ent in d.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            for field in (ent.get("vcardArray") or [None, []])[1]:
                if field[0] == "fn":
                    registrar = field[3]

    created = events.get("registration")
    age_days = None
    if created:
        try:
            age_days = (now() - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
        except ValueError:
            pass

    return {
        "domain": domain,
        "registrar": registrar,
        "created": created,
        "expires": events.get("expiration"),
        "updated": events.get("last changed"),
        "ageDays": age_days,
        "nameservers": [ns.get("ldhName", "").lower() for ns in d.get("nameservers") or []][:4],
        "status": d.get("status") or [],
    }


# ---------- 6. Geolocation (ip-api.com, free, no key) ----------
async def geo_locate(client, ip):
    res = await client.get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,timezone,proxy,hosting"},
        timeout=8,
    )
    d = res.json()
    if d.get("status") != "success":
        msg = d.get("message")
        return {"error": "Private IP, no public location" if msg == "private range" else msg or "Location lookup failed"}
    return d


# ---------- 7. Explainable risk scoring ----------
# Base score = the worst score from the reputation sources (VirusTotal, AbuseIPDB).
# Context signals (Tor, brand-new domain, known CVEs, proxy) then add points on top, each one listed as a factor
# so an analyst can see exactly why an indicator got its score.
def compute_risk(type_, vt, abuse, shodan, whois, geo, phishing):
    factors = []

    # base=True: a reputation score (the highest one wins); base=False: context points added on top
    def factor(source, text, points, tone, base=False):
        factors.append({"source": source, "text": text, "points": points, "tone": tone, "base": base})

    vt_score = None
    if vt and vt.get("stats") is not None:
        m = vt["stats"].get("malicious", 0)
        s = vt["stats"].get("suspicious", 0)
        vt_score = min(100, m * 12 + s * 6)  # each malicious engine = 12 pts, suspicious = 6 pts
        engines = sum(vt["stats"].values())
        if m or s:
            factor("VirusTotal", f"{m} malicious and {s} suspicious verdicts out of {engines} engines", vt_score, "bad", base=True)
        else:
            factor("VirusTotal", f"No detections from {engines} engines", 0, "good")
        if vt.get("threatLabel"):
            factor("VirusTotal", f"Classified as malware family “{vt['threatLabel']}”", 0, "bad")

    abuse_score = abuse.get("score") if abuse and isinstance(abuse.get("score"), int) else None
    if abuse_score is not None:
        if abuse_score:
            factor("AbuseIPDB", f"{abuse_score}% abuse confidence from {abuse.get('totalReports', 0)} reports", abuse_score, "bad", base=True)
        else:
            factor("AbuseIPDB", "No abuse reports in the last 90 days", 0, "good")
        if abuse.get("isWhitelisted"):
            factor("AbuseIPDB", "IP is on the AbuseIPDB whitelist", 0, "good")

    bonus = 0
    if abuse and abuse.get("isTor"):
        bonus += 15
        factor("AbuseIPDB", "Tor exit node: traffic is anonymised", 15, "warn")
    if geo and geo.get("proxy"):
        bonus += 10
        factor("ip-api", "Known proxy / VPN endpoint", 10, "warn")
    if shodan and shodan.get("vulns"):
        pts = min(20, len(shodan["vulns"]) * 2)
        bonus += pts
        factor("Shodan", f"{len(shodan['vulns'])} known CVEs on exposed services", pts, "warn")
    if whois and whois.get("ageDays") is not None and type_ in ("domain", "url"):
        if whois["ageDays"] < 30:
            bonus += 25
            factor("RDAP", f"Domain registered only {whois['ageDays']} days ago (common in phishing)", 25, "bad")
        elif whois["ageDays"] < 180:
            bonus += 10
            factor("RDAP", f"Young domain: {whois['ageDays']} days old", 10, "warn")
        elif whois["ageDays"] > 365 * 5:
            factor("RDAP", f"Long-established domain ({whois['ageDays'] // 365} years old)", 0, "good")

    if phishing and phishing["points"]:
        bonus += phishing["points"]
        for f in phishing["findings"]:
            factor("Phishing engine", f["text"], f["points"], f["severity"])

    parts = [v for v in (vt_score, abuse_score) if v is not None]
    # Offline heuristics can still score a brand-new domain no reputation source has seen yet
    score = min(100, (max(parts) if parts else 0) + bonus) if parts or bonus else None

    level = "Unknown"
    if score is not None:
        level = "Malicious" if score >= 60 else "Suspicious" if score >= 20 else "Clean"

    return {
        "score": score,
        "level": level,
        "vtScore": vt_score,
        "abuseScore": abuse_score,
        "bonus": bonus,
        "factors": factors,
        "summary": analyst_summary(type_, level, vt, abuse, shodan, whois, phishing),
        "actions": recommended_actions(type_, level, abuse, shodan),
    }


def analyst_summary(type_, level, vt, abuse, shodan, whois, phishing):
    name = {"ip": "IP address", "domain": "domain", "url": "URL", "hash": "file"}[type_]
    s = []
    if level == "Malicious":
        s.append(f"This {name} is assessed as MALICIOUS with high confidence.")
    elif level == "Suspicious":
        s.append(f"This {name} shows suspicious indicators and should be treated with caution.")
    elif level == "Clean":
        s.append(f"No meaningful threat activity was found for this {name}.")
    else:
        s.append(f"There is not enough intelligence to assess this {name}.")

    if vt and vt.get("stats"):
        m = vt["stats"].get("malicious", 0)
        if m:
            s.append(f"{m} antivirus engines flag it as malicious" + (f", most commonly as “{vt['threatLabel']}”." if vt.get("threatLabel") else "."))
    if abuse and abuse.get("totalReports"):
        s.append(f"It has been reported for abuse {abuse['totalReports']} times by {abuse.get('distinctUsers', 0)} distinct users in 90 days.")
    if abuse and abuse.get("categories"):
        top = ", ".join(c["name"].lower() for c in abuse["categories"][:3])
        s.append(f"Most reported activity: {top}.")
    if phishing and phishing.get("lookalike"):
        s.append(f"The name impersonates “{phishing['lookalike']}”, a strong sign of a phishing site.")
    if abuse and abuse.get("isTor"):
        s.append("It is a Tor exit node, so activity from it cannot be attributed to a single actor.")
    if shodan and shodan.get("vulns"):
        s.append(f"Shodan sees {len(shodan['ports'])} open ports and {len(shodan['vulns'])} known vulnerabilities on this host.")
    if whois and whois.get("ageDays") is not None and whois["ageDays"] < 180 and type_ in ("domain", "url"):
        s.append(f"The domain is only {whois['ageDays']} days old.")
    return " ".join(s)


def recommended_actions(type_, level, abuse, shodan):
    if level == "Malicious":
        actions = {
            "ip": ["Block the IP at the firewall / edge", "Search SIEM and firewall logs for connections to it in the last 90 days"],
            "domain": ["Block the domain on DNS filter and web proxy", "Search DNS and proxy logs for hosts that resolved it"],
            "url": ["Block the URL on the web proxy and email gateway", "Find and purge emails containing the link", "Reset credentials of users who clicked it"],
            "hash": ["Add the hash to the EDR blocklist", "Sweep endpoints for the file and isolate any infected host"],
        }[type_]
        return actions + ["Open an incident ticket and share the IOC with your team"]
    if level == "Suspicious":
        out = ["Add the indicator to a watchlist and alert on new activity", "Correlate with internal logs before blocking"]
        if abuse and abuse.get("isTor"):
            out.append("Decide on a policy for Tor traffic to sensitive services")
        return out
    if level == "Clean":
        out = ["No action needed; re-check if new activity appears"]
        if shodan and shodan.get("vulns"):
            out.append("If this host is yours, patch the exposed services with known CVEs")
        return out
    return ["Gather more context (logs, sandbox detonation) before deciding"]


# ---------- Routes ----------
@app.get("/api/health")
async def health():
    return {"ok": True, "virustotal": bool(VT_KEY), "abuseipdb": bool(ABUSE_KEY), "demoMode": demo_mode()}


@app.get("/api/lookup")
async def lookup(q: str = Query(""), refresh: bool = False):
    raw = refang(q.strip())
    type_ = detect_type(raw)
    if not type_:
        return JSONResponse(
            status_code=400,
            content={"error": "Enter a valid IP address, domain, URL or file hash (MD5, SHA-1 or SHA-256)."},
        )

    query = raw.lower() if type_ in ("hash", "domain") else raw

    if not refresh and not demo_mode():
        hit = cached_report(query)
        if hit:
            return hit

    started = time.perf_counter()
    ip, host = None, None
    if type_ == "ip":
        ip = query
    elif type_ == "domain":
        host = query
        ip = await resolve(query)
    elif type_ == "url":
        host = urlparse(query).hostname
        ip = await resolve(host)
        if host and is_ip(host):
            host = None

    public_ip = ip if ip and ipaddress.ip_address(ip).is_global else None

    async with httpx.AsyncClient(headers={"User-Agent": "ThreatLens/2.0"}) as client:
        vt, abuse, geo, shodan, whois = await asyncio.gather(
            source(f"vt:{type_}:{query}", lambda: virus_total(client, type_, query)),
            source(f"abuse:{ip}", lambda: abuse_ipdb(client, ip)) if ip else none(),
            source(f"geo:{ip}", lambda: geo_locate(client, ip)) if ip else none(),
            source(f"shodan:{public_ip}", lambda: shodan_internetdb(client, public_ip)) if public_ip else none(),
            source(f"rdap:{registrable_domain(host)}", lambda: rdap(client, registrable_domain(host))) if host else none(),
        )

    phishing = phishing_analysis(type_, query, host, registrable_domain(host) if host else None)
    risk = compute_risk(type_, vt, abuse, shodan, whois, geo, phishing)
    sources = [x for x in (vt, abuse, geo, shodan, whois) if x is not None]

    report = {
        "query": query,
        "type": type_,
        "resolvedIP": ip,
        "risk": risk,
        "mitre": mitre_mapping(type_, risk["level"], vt, abuse, shodan, whois, geo, phishing),
        "phishing": phishing,
        "sourcesQueried": len(sources) + 1,  # + the offline phishing / ATT&CK engine
        "durationMs": round((time.perf_counter() - started) * 1000),
        "virustotal": vt,
        "abuseipdb": abuse,
        "geo": geo,
        "shodan": shodan,
        "whois": whois,
        "checkedAt": now().isoformat(),
        "cached": False,
        "demo": demo_mode(),
    }
    # Only reports where VirusTotal answered are reused as cache; rate-limited ones are retried next time
    complete = not (vt or {}).get("error")
    report["id"] = save_report(report, complete)
    return report


@app.get("/api/report/{report_id}")
async def get_report(report_id: int):
    with db() as conn:
        row = conn.execute("SELECT id, report FROM lookups WHERE id = ?", (report_id,)).fetchone()
    if not row:
        return JSONResponse(status_code=404, content={"error": "Report not found"})
    return {**json.loads(row["report"]), "id": row["id"], "cached": True}


class ExtractBody(BaseModel):
    text: str


IOC_PATTERNS = [
    ("url", re.compile(r"https?://[^\s\"'<>()\[\]{}]+", re.I)),
    ("hash", re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("domain", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)),
]
# "invoice.pdf" looks like a domain; these file extensions are never real TLDs we care about
NOT_TLDS = {"exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "txt", "zip", "rar", "js", "png", "jpg", "jpeg",
            "gif", "ps1", "bat", "sh", "py", "html", "htm", "php", "vbs", "lnk", "iso", "msi", "tmp", "log", "csv", "json"}


@app.post("/api/extract")
async def extract(body: ExtractBody):
    found = extract_iocs(body.text)
    return {"indicators": found, "count": len(found)}


def extract_iocs(text):
    text = refang(text[:200_000])
    found, seen = [], set()
    url_hosts = set()

    for type_, pattern in IOC_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(0).rstrip(".,;:")
            if type_ == "url":
                url_hosts.add((urlparse(value).hostname or "").lower())
            if type_ == "domain":
                value = value.lower()
                if value.rsplit(".", 1)[-1] in NOT_TLDS or is_ip(value):
                    continue
            if type_ == "hash":
                value = value.lower()
            if type_ == "ip" and not ipaddress.ip_address(value).is_global:
                continue
            if value in seen:
                continue
            seen.add(value)
            found.append({"value": value, "type": type_, "insideUrl": type_ == "domain" and value in url_hosts})
    return found


@app.get("/api/history")
async def history(limit: int = 100):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, query, type, level, score, created_at FROM lookups ORDER BY id DESC LIMIT ?", (min(limit, 500),)
        ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/history")
async def clear_history():
    with db() as conn:
        conn.execute("DELETE FROM lookups")
    return {"ok": True}


@app.get("/api/stats")
async def stats():
    with db() as conn:
        rows = conn.execute("SELECT query, type, level, score, created_at, report FROM lookups").fetchall()
    durations = [d for d in (json.loads(r["report"]).get("durationMs") for r in rows) if d]

    # Latest verdict per unique indicator, so re-scanning the same IP doesn't inflate the numbers
    latest = {}
    for r in rows:
        latest[r["query"]] = r

    today = now().date()
    days = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    per_day = Counter(r["created_at"][:10] for r in rows)

    top = sorted((r for r in latest.values() if r["score"] is not None), key=lambda r: r["score"], reverse=True)[:8]
    return {
        "totalScans": len(rows),
        "avgDurationMs": round(sum(durations) / len(durations)) if durations else None,
        "uniqueIndicators": len(latest),
        "byLevel": Counter(r["level"] for r in latest.values()),
        "byType": Counter(r["type"] for r in latest.values()),
        "perDay": [{"date": d, "count": per_day.get(d, 0)} for d in days],
        "topThreats": [{"query": r["query"], "type": r["type"], "level": r["level"], "score": r["score"]} for r in top],
    }


# ---------- Offline demo mode routes ----------
class DemoBody(BaseModel):
    enabled: bool


@app.get("/api/demo")
async def demo_status():
    with db() as conn:
        keys = [r["key"] for r in conn.execute("SELECT key FROM fixtures").fetchall()]
    return {
        "enabled": demo_mode(),
        "recorded": len(keys),
        "vtIndicators": sorted(k.split(":", 2)[2] for k in keys if k.startswith("vt:")),
        "threatMap": "threatmap" in keys,
    }


@app.post("/api/demo")
async def set_demo(body: DemoBody):
    set_setting("demo_mode", body.enabled)
    return await demo_status()


# ---------- Live threat map ----------
# AbuseIPDB's blacklist = the IPs most reported for attacks worldwide right now. The free plan allows only
# 5 blacklist downloads a day, so the map is cached for 6 hours (and replayed in demo mode).
THREATMAP_TTL = timedelta(hours=6)


async def build_threat_map(client):
    res = await client.get(
        "https://api.abuseipdb.com/api/v2/blacklist",
        params={"confidenceMinimum": 100, "limit": 500},
        headers={"Key": ABUSE_KEY, "Accept": "application/json"},
        timeout=20,
    )
    if res.status_code == 429:
        return {"error": "AbuseIPDB blacklist limit reached (free plan: 5 downloads a day). Try again later."}
    if not res.is_success:
        return {"error": f"AbuseIPDB blacklist returned {res.status_code}"}
    entries = sorted(res.json()["data"], key=lambda d: d.get("lastReportedAt") or "", reverse=True)

    # Geolocate the 300 most recently reported attackers with ip-api's batch endpoint (100 per request)
    sample = entries[:300]
    located = {}
    for i in range(0, len(sample), 100):
        batch = [{"query": e["ipAddress"], "fields": "status,query,lat,lon,country,countryCode,city,isp,as"} for e in sample[i:i + 100]]
        r = await client.post("http://ip-api.com/batch", json=batch, timeout=15)
        if r.is_success:
            for g in r.json():
                if g.get("status") == "success":
                    located[g["query"]] = g

    points = []
    for e in sample:
        g = located.get(e["ipAddress"])
        if g:
            points.append({
                "ip": e["ipAddress"], "lat": g["lat"], "lon": g["lon"], "country": g.get("country"),
                "countryCode": g.get("countryCode"), "city": g.get("city"), "isp": g.get("isp"),
                "score": e.get("abuseConfidenceScore"), "lastReportedAt": e.get("lastReportedAt"),
            })

    countries = Counter(e.get("countryCode") or "??" for e in entries)
    names = {p["countryCode"]: p["country"] for p in points}
    return {
        "total": len(entries),
        "points": points,
        "countries": [{"code": c, "name": names.get(c, c), "count": n} for c, n in countries.most_common(10)],
        "fetchedAt": now().isoformat(),
    }


@app.get("/api/threatmap")
async def threat_map(refresh: bool = False):
    data = load_fixture("threatmap", None if demo_mode() else THREATMAP_TTL)
    if (data is None or refresh) and not demo_mode():
        if not ABUSE_KEY:
            return JSONResponse(status_code=400, content={"error": "AbuseIPDB API key is missing in server/.env"})
        async with httpx.AsyncClient(headers={"User-Agent": "ThreatLens/2.0"}) as client:
            fresh = await safe(build_threat_map(client))
        if fresh.get("error"):
            data = data or load_fixture("threatmap")  # fall back to an older map rather than nothing
            if data is None:
                return JSONResponse(status_code=502, content=fresh)
        else:
            save_fixture("threatmap", fresh)
            data = fresh
    if data is None:
        return JSONResponse(status_code=404, content={"error": "No threat map recorded yet. Open the map once while online."})

    # Overlay the threats this ThreatLens instance found itself
    with db() as conn:
        rows = conn.execute("SELECT report FROM lookups WHERE level IN ('Malicious', 'Suspicious') ORDER BY id DESC LIMIT 200").fetchall()
    mine, seen = [], set()
    for r in rows:
        rep = json.loads(r["report"])
        geo = rep.get("geo") or {}
        if geo.get("lat") is not None and rep["query"] not in seen:
            seen.add(rep["query"])
            mine.append({"query": rep["query"], "lat": geo["lat"], "lon": geo["lon"], "level": rep["risk"]["level"], "country": geo.get("country")})
    return {**data, "mine": mine}


# ---------- Email analyzer ----------
class EmailBody(BaseModel):
    raw: str


@app.post("/api/email")
async def email(body: EmailBody):
    if not body.raw.strip():
        return JSONResponse(status_code=400, content={"error": "Paste or upload a raw email (.eml)."})
    try:
        return analyze_email(body.raw[:5_000_000].encode("utf-8", "surrogateescape"))
    except Exception as err:
        return JSONResponse(status_code=400, content={"error": f"Couldn't parse that email: {err}"})


@app.get("/api/email/sample")
async def email_sample():
    return {"raw": (Path(__file__).parent / "samples" / "phishing_sample.eml").read_text(encoding="utf-8")}


if __name__ == "__main__":
    print(f"ThreatLens server running on http://localhost:{PORT}")
    print(f"VirusTotal key: {'loaded' if VT_KEY else 'MISSING'} | AbuseIPDB key: {'loaded' if ABUSE_KEY else 'MISSING'}")
    uvicorn.run(app, host="127.0.0.1", port=PORT)
