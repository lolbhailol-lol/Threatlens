# ThreatLens email analyzer: parses a raw .eml message and looks for the tricks phishing emails use.
# Runs fully offline; the IOCs it finds (links, sender IPs, attachment hashes) can then be scanned live.

import hashlib
import html
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from urllib.parse import urlparse

from heuristics import BRANDS, phishing_analysis

URGENCY = ["urgent", "immediately", "suspended", "verify your", "within 24 hours", "account locked", "unusual activity",
           "unusual sign-in", "password expires", "final notice", "action required", "confirm your", "limited time",
           "security alert", "will be closed", "update your payment", "kyc"]

RISKY_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "hta", "html", "htm", "iso", "img", "lnk",
             "msi", "jar", "wsf", "docm", "xlsm", "pptm", "one", "svg"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip"}

IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
LINK_RE = re.compile(r"<a\s[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")


def _domain(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _base(domain):
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _auth_results(msg):
    text = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", text, re.I)
        out[mech] = m.group(1).lower() if m else None
    if not out["spf"]:
        rs = msg.get("Received-SPF")
        if rs:
            out["spf"] = str(rs).split()[0].lower()
    return out


def _route(msg):
    """Received headers, oldest hop first, with the public IP each hop came from."""
    hops = []
    for h in reversed(msg.get_all("Received") or []):
        h = " ".join(str(h).split())
        frm = re.search(r"from\s+(\S+)", h, re.I)
        by = re.search(r"by\s+(\S+)", h, re.I)
        ip = None
        for cand in IP_RE.findall(h.split(" by ")[0] if " by " in h else h):
            try:
                if ipaddress.ip_address(cand).is_global:
                    ip = cand
                    break
            except ValueError:
                continue
        date = h.rsplit(";", 1)[-1].strip() if ";" in h else None
        hops.append({"from": frm.group(1) if frm else None, "by": by.group(1) if by else None, "ip": ip, "date": date})
    return hops


def analyze_email(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    findings = []

    def find(text, points, severity, area):
        findings.append({"text": text, "points": points, "severity": severity, "area": area})

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = _domain(from_addr)
    reply_to = [a for _, a in getaddresses([str(h) for h in msg.get_all("Reply-To") or []])]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    subject = str(msg.get("Subject", ""))

    # ---- Sender authentication ----
    auth = _auth_results(msg)
    for mech, pts in (("spf", 15), ("dkim", 10), ("dmarc", 20)):
        v = auth[mech]
        if v in ("fail", "softfail", "permerror"):
            why = {
                "spf": f"the sending server is not authorised to send for {from_dom or 'this domain'}",
                "dkim": "the message signature is invalid or was tampered with",
                "dmarc": f"the message fails {from_dom or 'the domain'}'s own anti-spoofing policy",
            }[mech]
            find(f"{mech.upper()} {v}: {why}", pts, "bad", "Authentication")
        elif v in (None, "none", "neutral", "temperror"):
            find(f"{mech.upper()} {'missing' if v is None else v}: sender cannot be verified", pts // 3, "warn", "Authentication")

    # ---- Header tricks ----
    for r in reply_to:
        if _domain(r) and _base(_domain(r)) != _base(from_dom):
            find(f"Reply-To ({r}) differs from the sender: replies go to someone else", 15, "bad", "Headers")
    if return_path and _domain(return_path) and _base(_domain(return_path)) != _base(from_dom):
        find(f"Return-Path domain ({_domain(return_path)}) doesn't match the From domain", 10, "warn", "Headers")
    name_l = from_name.lower().replace(" ", "")
    for brand in BRANDS:
        if len(brand) >= 4 and brand in name_l and brand not in from_dom.replace("-", ""):
            find(f"Display name “{from_name}” claims to be {brand} but the address is {from_addr}", 25, "bad", "Headers")
            break
    if "@" in from_name and _domain(from_name) != from_dom:
        find("Display name contains a different email address (display-name spoofing)", 20, "bad", "Headers")
    sender_check = phishing_analysis("domain", from_dom, from_dom, _base(from_dom)) if from_dom else None
    if sender_check and sender_check["lookalike"]:
        find(f"Sender domain {from_dom} is a look-alike of {sender_check['lookalike']}", 30, "bad", "Headers")

    # ---- Body: links, urgency ----
    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            name = filename or "unnamed"
            exts = name.lower().split(".")[1:]
            risky = bool(exts) and exts[-1] in RISKY_EXT
            double = len(exts) >= 2 and exts[-2] in DOC_EXT and exts[-1] in RISKY_EXT
            attachments.append({
                "name": name, "contentType": ctype, "size": len(payload),
                "md5": hashlib.md5(payload).hexdigest(), "sha256": hashlib.sha256(payload).hexdigest(),
                "risky": risky, "doubleExtension": double,
            })
            if double:
                find(f"Attachment “{name}” hides a .{exts[-1]} file behind a fake .{exts[-2]} extension", 30, "bad", "Attachments")
            elif risky:
                find(f"Attachment “{name}” is an executable / script type (.{exts[-1]})", 20, "bad", "Attachments")
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if ctype == "text/html":
            html_parts.append(content)
        elif ctype == "text/plain":
            text_parts.append(content)

    links = []
    for body in html_parts:
        for href, inner in LINK_RE.findall(body):
            shown = html.unescape(TAG_RE.sub("", inner)).strip()
            href = html.unescape(href).strip()
            if not href.lower().startswith("http"):
                continue
            real = (urlparse(href).hostname or "").lower()
            shown_host = ""
            m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", shown, re.I)
            if m:
                shown_host = m.group(1).lower()
            mismatch = bool(shown_host) and _base(shown_host) != _base(real)
            links.append({"text": shown[:120], "href": href, "host": real, "mismatch": mismatch})
            if mismatch:
                find(f"Link text shows {shown_host} but actually goes to {real}", 30, "bad", "Links")
    for body in text_parts:
        for href in re.findall(r"https?://[^\s<>\"')]+", body):
            if not any(l["href"] == href for l in links):
                links.append({"text": "", "href": href, "host": (urlparse(href).hostname or "").lower(), "mismatch": False})

    for l in links:
        check = phishing_analysis("url", l["href"], l["host"], _base(l["host"])) if l["host"] else None
        l["phishing"] = check["findings"] if check else []
        if check and check["lookalike"]:
            find(f"Link to {l['host']} impersonates {check['lookalike']}", 25, "bad", "Links")

    full_text = (subject + " " + " ".join(text_parts) + " " + " ".join(TAG_RE.sub(" ", h) for h in html_parts)).lower()
    urgent = [w for w in URGENCY if w in full_text]
    if urgent:
        find(f"Pressure / urgency language: {', '.join(urgent[:4])}", min(15, 5 * len(urgent)), "warn", "Content")

    # De-duplicate identical findings (e.g. the same look-alike link twice)
    seen, unique = set(), []
    for f in findings:
        if f["text"] not in seen:
            seen.add(f["text"])
            unique.append(f)
    findings = unique

    route = _route(msg)
    origin_ip = next((h["ip"] for h in route if h["ip"]), None)

    score = min(100, sum(f["points"] for f in findings))
    level = "Malicious" if score >= 60 else "Suspicious" if score >= 20 else "Clean"

    iocs = []
    if origin_ip:
        iocs.append({"value": origin_ip, "type": "ip", "why": "Originating mail server"})
    for l in links:
        iocs.append({"value": l["href"], "type": "url", "why": "Link in body"})
    for a in attachments:
        iocs.append({"value": a["sha256"], "type": "hash", "why": f"Attachment {a['name']}"})
    if from_dom:
        iocs.append({"value": from_dom, "type": "domain", "why": "Sender domain"})

    date = None
    try:
        date = parsedate_to_datetime(str(msg.get("Date"))).isoformat() if msg.get("Date") else None
    except Exception:
        pass

    return {
        "summary": {
            "from": str(msg.get("From", "")), "fromAddress": from_addr, "fromDomain": from_dom,
            "replyTo": reply_to, "returnPath": return_path, "to": str(msg.get("To", "")),
            "subject": subject, "date": date, "messageId": str(msg.get("Message-ID", "")),
        },
        "auth": auth,
        "route": route,
        "originIP": origin_ip,
        "links": links,
        "attachments": attachments,
        "findings": findings,
        "score": score,
        "level": level,
        "iocs": iocs,
    }
