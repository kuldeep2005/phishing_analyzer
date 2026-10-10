#!/usr/bin/env python3
"""
Phishing Email Analyzer
Checks an email's text for common phishing red flags and gives a risk score.
No installs needed - uses only the Python standard library.

Usage:
    python phishing_analyzer.py --demo            # run on built-in sample emails
    python phishing_analyzer.py email.txt         # analyze an email saved as a text file
    python phishing_analyzer.py email.txt --json  # output as JSON
"""

import argparse
import difflib
import json
import re
import sys
from email import message_from_string
from email.utils import parseaddr
from urllib.parse import urlparse

# ---------- Settings (easy to edit) ----------

BRANDS = ["paypal", "microsoft", "apple", "amazon", "google", "netflix",
          "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
          "dhl", "fedex", "usps", "linkedin", "docusign"]

URGENT_WORDS = ["urgent", "immediately", "act now", "within 24 hours",
                "account suspended", "account locked", "verify your account",
                "final notice", "limited time", "unusual activity",
                "confirm your identity", "action required"]

SENSITIVE_REQUESTS = ["password", "social security", "ssn", "credit card",
                      "gift card", "bank account", "login details", "pin number",
                      "wire transfer"]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "is.gd", "buff.ly", "cutt.ly", "rb.gy"}

SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".click", ".work", ".gq",
                   ".tk", ".ml", ".cf", ".country", ".support"}

RISKY_ATTACHMENTS = [".exe", ".scr", ".bat", ".js", ".vbs", ".iso",
                     ".docm", ".xlsm", ".html", ".htm", ".zip", ".lnk"]

FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"}

URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# Each finding adds points to the risk score (max 100)
POINTS = {
    "urgent_language": 10,
    "sensitive_request": 15,
    "display_name_spoof": 20,
    "reply_to_mismatch": 15,
    "lookalike_domain": 25,
    "ip_url": 20,
    "at_symbol_url": 15,
    "shortened_url": 10,
    "suspicious_tld": 10,
    "no_https": 5,
    "punycode": 15,
    "many_subdomains": 8,
    "risky_attachment": 15,
}

# ---------- Helper functions ----------

def get_domain(address):
    """Return the domain part of an email address."""
    return address.split("@")[-1].lower().strip() if "@" in address else ""


def normalize(text):
    """Turn tricks like paypa1 / micr0soft into normal letters."""
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})
    return text.lower().translate(table)


def is_lookalike(domain):
    """Return the brand name this domain is trying to imitate, or None."""
    parts = domain.split(".")
    main = parts[-2] if len(parts) >= 2 else domain
    cleaned = normalize(main).replace("-", "")
    for brand in BRANDS:
        if main == brand:
            continue  # exact brand name is probably the real site
        if cleaned == brand:  # e.g. paypa1 -> paypal
            return brand
        if brand in cleaned and main != brand:  # e.g. paypal-secure
            return brand
        if difflib.SequenceMatcher(None, cleaned, brand).ratio() >= 0.85:
            return brand  # e.g. paypall, amazom
    return None


def extract_parts(raw):
    """Split raw email text into headers + body. Works with or without headers."""
    msg = message_from_string(raw)
    if msg.is_multipart():
        body = ""
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        body = payload.decode(errors="ignore") if payload else str(msg.get_payload())
    return msg, body


# ---------- Main analysis ----------

def analyze(raw_email):
    msg, body = extract_parts(raw_email)
    findings = []  # list of (check_name, explanation)

    from_name, from_addr = parseaddr(msg.get("From", ""))
    reply_name, reply_addr = parseaddr(msg.get("Reply-To", ""))
    subject = msg.get("Subject", "")
    from_domain = get_domain(from_addr)
    full_text = f"{subject}\n{body}".lower()

    # 1. Urgent / pressure language
    hits = [w for w in URGENT_WORDS if w in full_text]
    if hits:
        findings.append(("urgent_language", f"Pressure words found: {', '.join(hits[:4])}"))

    # 2. Asks for sensitive info
    hits = [w for w in SENSITIVE_REQUESTS if w in full_text]
    if hits:
        findings.append(("sensitive_request", f"Mentions sensitive info: {', '.join(hits[:4])}"))

    # 3. Display name says a brand, but the email domain does not match
    for brand in BRANDS:
        if brand in normalize(from_name).replace(" ", "") and brand not in from_domain:
            findings.append(("display_name_spoof",
                             f"Sender name says '{from_name}' but email is from {from_domain}"))
            break

    # 4. Reply-To goes somewhere different than From
    if reply_addr and get_domain(reply_addr) != from_domain:
        findings.append(("reply_to_mismatch",
                         f"Replies go to {get_domain(reply_addr)}, not {from_domain}"))

    # 5. Lookalike sender domain
    if from_domain and from_domain not in FREE_MAIL:
        brand = is_lookalike(from_domain)
        if brand:
            findings.append(("lookalike_domain",
                             f"Sender domain '{from_domain}' looks like '{brand}'"))

    # 6. Check every link
    urls = list(dict.fromkeys(URL_REGEX.findall(f"{subject}\n{body}")))
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            findings.append(("ip_url", f"Link uses a raw IP address: {url}"))
        if "@" in parsed.netloc:
            findings.append(("at_symbol_url", f"Link hides its real destination with '@': {url}"))
        if host in URL_SHORTENERS:
            findings.append(("shortened_url", f"Shortened link hides destination: {url}"))
        if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
            findings.append(("suspicious_tld", f"Link uses a risky domain ending: {host}"))
        if parsed.scheme == "http":
            findings.append(("no_https", f"Link is not encrypted (http): {url}"))
        if "xn--" in host:
            findings.append(("punycode", f"Link uses lookalike characters (punycode): {host}"))
        if host.count(".") >= 4:
            findings.append(("many_subdomains", f"Link has too many subdomains: {host}"))
        brand = is_lookalike(host) if host and not re.fullmatch(r"[\d.]+", host) else None
        if brand:
            findings.append(("lookalike_domain", f"Link domain '{host}' looks like '{brand}'"))

    # 7. Risky attachment names mentioned or attached
    names = []
    if msg.is_multipart():
        names = [p.get_filename() for p in msg.walk() if p.get_filename()]
    names += re.findall(r"[\w\-.]+\.(?:exe|scr|bat|js|vbs|iso|docm|xlsm|html|htm|zip|lnk)\b", body, re.I)
    for n in names:
        if any(n.lower().endswith(ext) for ext in RISKY_ATTACHMENTS):
            findings.append(("risky_attachment", f"Risky file type: {n}"))

    # Score: count each type of check once so one problem can't max the score
    score = min(100, sum(POINTS[k] for k in {name for name, _ in findings}))
    if score >= 60:
        verdict = "HIGH RISK - likely phishing"
    elif score >= 30:
        verdict = "MEDIUM RISK - be suspicious"
    else:
        verdict = "LOW RISK - no major red flags"

    return {
        "from": f"{from_name} <{from_addr}>",
        "subject": subject,
        "links_found": urls,
        "findings": [{"check": c, "detail": d} for c, d in findings],
        "score": score,
        "verdict": verdict,
    }


def print_report(result):
    line = "=" * 60
    print(line)
    print("PHISHING ANALYSIS REPORT")
    print(line)
    print(f"From    : {result['from']}")
    print(f"Subject : {result['subject']}")
    print(f"Links   : {len(result['links_found'])}")
    print("-" * 60)
    if result["findings"]:
        for i, f in enumerate(result["findings"], 1):
            print(f"[{i}] {f['detail']}")
    else:
        print("No red flags found.")
    print("-" * 60)
    print(f"RISK SCORE: {result['score']}/100")
    print(f"VERDICT   : {result['verdict']}")
    print(line + "\n")


# ---------- Demo emails ----------

DEMO_PHISHING = """From: "PayPal Security" <support@paypa1-secure.xyz>
Reply-To: helpdesk@mail-recovery.top
Subject: URGENT: Your account is suspended

Dear customer,

We noticed unusual activity. Your account is locked. You must verify your
account immediately or it will be closed within 24 hours.

Confirm your password and bank account details here:
http://192.168.44.12/paypal/login

Or use this link: http://bit.ly/3xFakeLnk

Open the attached file invoice.zip for details.
"""

DEMO_SAFE = """From: "Maria Lopez" <maria@ucmo.edu>
Subject: Study group on Thursday

Hi everyone,

Reminder that our study group meets Thursday at 4 PM in the library.
Notes are here: https://www.ucmo.edu/library

See you there!
Maria
"""


def main():
    parser = argparse.ArgumentParser(description="Phishing Email Analyzer")
    parser.add_argument("file", nargs="?", help="Path to a text file with the email")
    parser.add_argument("--demo", action="store_true", help="Run on sample emails")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    if args.demo:
        emails = [("Sample 1 (phishing)", DEMO_PHISHING), ("Sample 2 (safe)", DEMO_SAFE)]
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                emails = [(args.file, f.read())]
        except FileNotFoundError:
            sys.exit(f"File not found: {args.file}")
    else:
        parser.print_help()
        sys.exit(1)

    for name, raw in emails:
        result = analyze(raw)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f">>> {name}")
            print_report(result)


if __name__ == "__main__":
    main()
