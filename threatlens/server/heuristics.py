# ThreatLens offline analysis: phishing / lookalike-domain heuristics and MITRE ATT&CK mapping.
# These run locally with no API calls, so they still work for brand-new phishing domains
# that VirusTotal and AbuseIPDB have never seen.

import math
import re
from collections import Counter
from urllib.parse import urlparse

# Brands most often impersonated in phishing (global + Indian banking / payments)
BRANDS = [
    "paypal", "apple", "microsoft", "office365", "outlook", "google", "gmail", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "icloud", "coinbase", "binance",
    "metamask", "chase", "wellsfargo", "bankofamerica", "dhl", "fedex", "steam", "roblox", "docusign",
    "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank", "axisbank", "kotak", "paytm", "phonepe",
    "flipkart", "irctc", "incometax",
]

# Look-alike characters attackers swap in: paypa1 -> paypal, rnicrosoft -> microsoft
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"), ("@", "a"), ("$", "s")]

# Cheap / free TLDs heavily abused for phishing and malware
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work",
              "rest", "fit", "cfd", "sbs", "lol", "quest", "buzz", "monster", "cyou", "icu"}

LURE_WORDS = ["login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "wallet",
              "banking", "password", "confirm", "unlock", "suspended", "billing", "invoice", "support", "kyc", "refund"]

ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def unglyph(s):
    for fake, real in HOMOGLYPHS:
        s = s.replace(fake, real)
    return s


def entropy(s):
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def phishing_analysis(type_, query, host, registrable):
    """Score a domain or URL for phishing traits. Returns findings with points, like the risk engine."""
    if type_ not in ("domain", "url") or not host:
        return None

    findings = []

    def find(text, points, severity):
        findings.append({"text": text, "points": points, "severity": severity})

    host = host.lower()
    labels = host.split(".")
    tld = labels[-1]
    main = registrable.split(".")[0] if registrable else labels[0]
    tokens = [t for t in re.split(r"[.\-_]", host) if t]

    # 1. Brand impersonation
    lookalike = None
    if main not in BRANDS:
        for tok in tokens:
            fixed = unglyph(tok)
            for brand in BRANDS:
                if tok == brand:
                    lookalike = brand
                    find(f"Uses the brand name “{brand}” on a domain that isn't {brand}'s", 25, "bad")
                elif fixed == brand:
                    lookalike = brand
                    find(f"Look-alike of “{brand}” using character substitution (“{tok}”)", 45, "bad")
                elif len(brand) >= 6 and len(tok) >= 6 and levenshtein(tok, brand) == 1:
                    lookalike = brand
                    find(f"Typosquat of “{brand}”: “{tok}” is one character off", 40, "bad")
                if lookalike:
                    break
            if lookalike:
                break

    # 2. Internationalised (punycode) domain: can render as a perfect visual clone
    if any(lbl.startswith("xn--") for lbl in labels):
        find("Punycode (IDN) domain: may visually impersonate another site (homograph attack)", 20, "bad")

    # 3. Risky TLD
    if tld in RISKY_TLDS:
        find(f".{tld} is a low-cost TLD frequently abused for phishing and malware", 10, "warn")

    # 4. Lure words in the hostname or path
    path = urlparse(query).path.lower() if type_ == "url" else ""
    lures = sorted({w for w in LURE_WORDS if w in host or w in path})
    if lures:
        find(f"Phishing lure words: {', '.join(lures[:4])}", min(15, 5 * len(lures)), "warn")

    # 5. Machine-generated looking name (Domain Generation Algorithm)
    # Hyphenated names ("secure-paypal-login") are human-made, so only unbroken strings are checked
    dga = len(main) >= 12 and entropy(main) > 3.5 and sum(ch.isdigit() for ch in main) >= 2
    if "-" not in main and (dga or (len(main) >= 16 and entropy(main) > 3.9)):
        find(f"Random-looking name “{main}” (entropy {entropy(main):.1f}): typical of DGA malware domains", 20, "bad")

    # 6. Structural URL tricks
    if type_ == "url":
        if "@" in query.split("//", 1)[-1].split("/", 1)[0]:
            find("“@” in the URL hides the real destination host", 20, "bad")
        if len(query) > 100:
            find(f"Very long URL ({len(query)} characters), often used to hide the real domain", 5, "warn")
    if len(labels) > 4:
        find(f"Deep subdomain nesting ({len(labels)} levels)", 10, "warn")

    return {
        "points": min(60, sum(f["points"] for f in findings)),
        "findings": findings,
        "lookalike": lookalike,
    }


def abuse_category_counts(reports):
    counts = Counter()
    for r in reports or []:
        for c in r.get("categories") or []:
            if c in ABUSE_CATEGORIES:
                counts[ABUSE_CATEGORIES[c]] += 1
    return [{"name": n, "count": c} for n, c in counts.most_common(8)]


def mitre_mapping(type_, level, vt, abuse, shodan, whois, geo, phishing):
    """Translate the evidence into MITRE ATT&CK techniques so the result speaks the analyst's language."""
    out = {}

    def add(tid, name, tactic, reason):
        if tid not in out:
            url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
            out[tid] = {"id": tid, "name": name, "tactic": tactic, "reason": reason, "url": url}

    detections = " ".join(d["result"].lower() for d in (vt or {}).get("detections") or [])
    cats = {c["name"] for c in (abuse or {}).get("categories") or []}

    if phishing and phishing["findings"] and phishing["points"] >= 25 or "phish" in detections or "Phishing" in cats:
        add("T1566.002", "Phishing: Spearphishing Link", "Initial Access", "Indicator shows phishing traits or is flagged as phishing")
    if phishing and phishing.get("lookalike"):
        add("T1583.001", "Acquire Infrastructure: Domains", "Resource Development", f"Look-alike domain registered to impersonate {phishing['lookalike']}")
    if whois and whois.get("ageDays") is not None and whois["ageDays"] < 30:
        add("T1583.001", "Acquire Infrastructure: Domains", "Resource Development", "Freshly registered domain")
    if phishing and any("DGA" in f["text"] for f in phishing["findings"]):
        add("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control", "Random-looking, algorithmically generated domain name")
    if type_ == "hash" and level in ("Malicious", "Suspicious"):
        add("T1204.002", "User Execution: Malicious File", "Execution", "File is detected as malware by antivirus engines")
    if abuse and abuse.get("isTor"):
        add("T1090.003", "Proxy: Multi-hop Proxy", "Command and Control", "Tor exit node used to anonymise traffic")
    elif geo and geo.get("proxy"):
        add("T1090", "Proxy", "Command and Control", "Known proxy / VPN endpoint")
    if cats & {"Brute-Force", "SSH", "FTP Brute-Force"}:
        add("T1110", "Brute Force", "Credential Access", "Reported for brute-force / SSH login attacks")
    if "Port Scan" in cats:
        add("T1595", "Active Scanning", "Reconnaissance", "Reported for port scanning")
    if cats & {"Web App Attack", "SQL Injection"}:
        add("T1190", "Exploit Public-Facing Application", "Initial Access", "Reported for web application / SQL injection attacks")
    if "DDoS Attack" in cats:
        add("T1498", "Network Denial of Service", "Impact", "Reported for DDoS attacks")
    if "Email Spam" in cats:
        add("T1566", "Phishing", "Initial Access", "Reported for sending spam / malicious email")
    if shodan and shodan.get("vulns") and level != "Clean":
        add("T1584.004", "Compromise Infrastructure: Server", "Resource Development", "Vulnerable exposed services: host may be compromised and abused")
    if any(w in detections for w in ("c2", "botnet", "command and control", "cnc")):
        add("T1071", "Application Layer Protocol", "Command and Control", "Engines label it as command-and-control / botnet infrastructure")

    return list(out.values())
