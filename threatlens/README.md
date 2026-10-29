# ThreatLens: Cyber Threat Intelligence Platform

ThreatLens helps a security analyst answer one question fast: **"Is this IP, domain, URL or file dangerous, and what should I do about it?"**

You give it an indicator of compromise (IOC). ThreatLens queries **five intelligence sources in parallel** and combines the results into one **explainable risk score**. It also writes a plain-English **analyst summary** and a list of **recommended actions**.

## Features

| Feature | What it does |
|---|---|
| **Multi-source enrichment** | VirusTotal (70+ AV engines), AbuseIPDB (crowd abuse reports), Shodan InternetDB (open ports and CVEs), RDAP/WHOIS (domain age), ip-api (geolocation, proxy and hosting detection) |
| **Zero-day phishing detection** | An offline engine catches brand look-alikes (`paypa1.com`, `rnicrosoft.com`), typosquats, punycode homographs, DGA-style names, risky TLDs and lure words. It works even when no reputation feed has seen the domain yet. |
| **MITRE ATT&CK mapping** | Evidence is translated into ATT&CK techniques (e.g. T1566.002 Spearphishing Link, T1110 Brute Force, T1090.003 Multi-hop Proxy), including AbuseIPDB attack categories |
| **Detection rule generator** | One click gives ready-to-deploy rules: firewall (iptables / Windows), DNS sinkhole, Suricata/Snort, Sigma, YARA, Splunk SPL, Microsoft KQL, and an endpoint hash sweep |
| **Explainable risk score** | Shows every factor that moved the score and how many points it added. No black box. |
| **Analyst summary and playbook** | Auto-generated verdict narrative, plus response actions tailored to the indicator type |
| **IOC extractor** | Paste a phishing email or threat report and it pulls out every IP, domain, URL and hash. Handles defanged IOCs (`hxxp://evil[.]com`) and skips file names and private IPs. |
| **Bulk scanning** | Scans up to 25 indicators in one batch, paced to the VirusTotal free-tier rate limit. Exports to CSV. |
| **Dashboard and history** | Every scan is stored in SQLite. Shows verdict breakdown, scans per day, highest-risk indicators and a filterable history. |
| **Smart caching** | Repeated lookups within 1 hour come from the local cache, saving API quota. A "Re-scan live" button forces a fresh check. |
| **Reporting** | Export a printable PDF report or JSON, or copy the IOC in defanged form for safe sharing |

## Why ThreatLens stands out

| | Single-source free tools (VirusTotal, AbuseIPDB, Shodan) | Enterprise TI platforms | **ThreatLens** |
|---|---|---|---|
| Sources in one view | 1 each | Many | **5 + offline engine** |
| Explains its score | No | Partly | **Every point traced to a reason** |
| Brand-new phishing domains | Missed until reported | Varies | **Flagged offline** |
| Turns intel into rules | No | Partly | **8 rule formats** |
| Data privacy | Cloud | Cloud | **Self-hosted** |
| Cost | Free, rate-limited | Enterprise licence | **Free, open source** |

**Pitch in one line:** ThreatLens turns a nine-tab manual investigation into one search: five intelligence sources, one explainable verdict and ready-to-deploy defences, in about 3 seconds.

ThreatLens doesn't replace VirusTotal or AbuseIPDB. It builds on them. The value is in **combining** the sources, **explaining** the verdict and helping the analyst **act** on it. The in-app **"Why ThreatLens"** tab has the full comparison.

## Architecture

```
 Browser (React + Vite + Recharts)
        │  /api/*  (Vite dev proxy)
        ▼
 Python FastAPI server ── asyncio.gather ──┬─ VirusTotal API v3
   • indicator detection + refang          ├─ AbuseIPDB API v2
   • risk engine (explainable)             ├─ Shodan InternetDB
   • analyst summary / playbook            ├─ RDAP (WHOIS)
   • IOC extractor (regex)                 └─ ip-api.com
   • heuristics.py: offline phishing / DGA engine + MITRE ATT&CK mapper
        │
        ▼
 SQLite (threatlens.db): scan history + 1-hour cache
```

**Security by design:** the API keys stay on the server, so the browser never sees them. If one source fails, the report still works: each source is isolated and shows its own error.

### How the risk score works

1. **Base score** = the higher of the two reputation scores:
   - VirusTotal: 12 points per malicious engine and 6 per suspicious engine, capped at 100
   - AbuseIPDB: its abuse confidence %
2. **Context points** are added on top:

   | Signal | Points |
   |---|---|
   | Tor exit node | +15 |
   | Proxy / VPN | +10 |
   | Known CVEs | +2 each, up to +20 |
   | Domain under 30 days old | +25 |
   | Domain under 6 months old | +10 |
   | Phishing engine findings (look-alike, punycode, lures, ...) | up to +60 |
3. The total is capped at 100. **60 or more = Malicious, 20 or more = Suspicious**, anything lower = Clean.

## Setup

You need Python 3.10+ and Node.js 18+.

```bash
# Backend
cd server
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env          # then paste your keys into .env
python main.py                  # http://localhost:5000

# Frontend (new terminal)
cd client
npm install
npm run dev                     # open http://localhost:5173
```

Free API keys:
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AbuseIPDB: https://www.abuseipdb.com/account/api

Shodan InternetDB, RDAP and ip-api don't need keys.

## API

| Route | Description |
|---|---|
| `GET /api/health` | Server status and which API keys are loaded |
| `GET /api/lookup?q=<ioc>[&refresh=1]` | Full enriched report (cached for 1 hour unless `refresh=1`) |
| `GET /api/report/{id}` | A stored report from history |
| `POST /api/extract` `{text}` | Extract IOCs from free text |
| `GET /api/history` / `DELETE /api/history` | List or clear scan history |
| `GET /api/stats` | Dashboard aggregates |

Interactive API docs (auto-generated by FastAPI): http://localhost:5000/docs

## Demo walkthrough (about 6 minutes)

0. **Open on the "Why ThreatLens" tab.** Walk through the problem, the 9-steps-vs-1 comparison and the comparison table (about 1 minute).

1. **Investigate tab: click "Tor exit node."** Point out:
   - the 100/100 gauge
   - the analyst summary and recommended actions
   - the **"Why this score?"** list (explainability)
   - the Shodan open ports and the map
2. **Click "EICAR test virus hash."** It's a file hash, and 60+ AV engines flag it. Show the engine table and the malware family.
3. **Click "Zero-day phishing URL."** This is the wow moment. VirusTotal has **no record** of this URL, yet ThreatLens marks it **Malicious**:
   - it spotted "paypa1" impersonating PayPal, plus the lure words
   - it mapped the finding to MITRE T1566.002
   - it generated a DNS sinkhole rule and a KQL query to find emails containing the link
4. **Click "google.com."** It comes out Clean, and RDAP shows the domain is decades old. That shows the score isn't just "always red".
5. **Bulk tab: click "Load sample phishing email," then "Extract indicators."**
   - Show that the defanged `hxxps://...[.]com` was understood.
   - Click **Scan selected** and point out the rate-limit-aware queue.
   - Export the results to CSV.
6. **Dashboard tab:** show the stats, charts and history, then click a row to reopen a stored report.
7. **Back on a report: click "Export PDF"** to show the printable incident report.
8. **Optional:** open http://localhost:5000/docs to show the auto-documented REST API.

## Notes and limits

- The VirusTotal free tier allows 4 lookups per minute. Bulk scans wait between live lookups automatically, and cached results don't count.
- The AbuseIPDB free tier allows 1,000 checks per day.
- Domains and URLs are resolved to an IP, so AbuseIPDB, Shodan and geolocation work for them too.

## Possible future work

- Sandbox detonation for files
- Scheduled watchlists that alert when a verdict changes
- User accounts with role-based access
- STIX/TAXII export for sharing with other security tools
