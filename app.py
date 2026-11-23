
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phishing URL & Domain Security Analyzer
=======================================
A single-file Streamlit dashboard that analyses a URL for phishing indicators:

  * Structural / heuristic URL analysis (IP hosts, '@' tricks, hyphens, dots, '//',
    risky TLDs, length, shorteners, punycode, keywords ...)
  * Typosquatting & brand-impersonation detection (leetspeak, homoglyphs,
    edit distance, brand-in-subdomain tricks)
  * Live SSL/TLS certificate inspection (validity, expiry, issuer, hostname match)
  * Optional safe redirect-chain resolution (no page body is downloaded)
  * Dynamic 0-100 phishing risk score with LOW / MEDIUM / HIGH classification
  * Actionable mitigation advice and a downloadable audit report (.md / .txt)

Run locally:   streamlit run app.py        (see instructions at the bottom of file)
"""

import hashlib
import html
import ipaddress
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st

# ----------------------------------------------------------------------------
# CONSTANTS & THREAT-INTEL DATA
# ----------------------------------------------------------------------------
APP_NAME = "Phishing URL & Domain Security Analyzer"
APP_VERSION = "1.0.0"

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "zip", "mov", "gq", "ml", "ga", "cf", "click", "work",
    "loan", "icu", "buzz", "rest", "monster", "cam", "country", "kim", "men",
    "review", "download", "racing", "party", "science", "date", "stream", "bid",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "lnkd.in", "s.id", "bl.ink", "v.gd", "soo.gd", "trib.al", "adf.ly",
    "bit.do", "mcaf.ee", "qr.ae",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "secure", "account",
    "banking", "confirm", "password", "wallet", "suspend", "unlock", "billing",
    "invoice", "support", "recover", "validate", "authenticate",
]

# Second-level public suffixes (so "bbc.co.uk" is parsed as registered domain bbc.co.uk)
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in",
    "net.in", "org.in", "gov.in", "ac.in", "co.jp", "com.br", "com.cn", "co.nz",
    "co.za", "com.mx", "com.sg", "com.tr", "com.hk", "co.kr",
}

# Monitored brands: key (lowercase token) -> display name + official domains
BRANDS = {
    "google": {"name": "Google", "domains": {"google.com", "google.co.in", "google.co.uk", "gstatic.com", "googleapis.com", "googleusercontent.com", "youtube.com", "gmail.com"}},
    "paypal": {"name": "PayPal", "domains": {"paypal.com", "paypal.me", "paypalobjects.com"}},
    "amazon": {"name": "Amazon", "domains": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp", "amazonaws.com"}},
    "facebook": {"name": "Facebook", "domains": {"facebook.com", "fb.com", "fbcdn.net", "meta.com", "messenger.com"}},
    "instagram": {"name": "Instagram", "domains": {"instagram.com"}},
    "whatsapp": {"name": "WhatsApp", "domains": {"whatsapp.com", "whatsapp.net"}},
    "microsoft": {"name": "Microsoft", "domains": {"microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com", "outlook.com", "windows.com", "azure.com"}},
    "apple": {"name": "Apple", "domains": {"apple.com", "icloud.com"}},
    "netflix": {"name": "Netflix", "domains": {"netflix.com"}},
    "linkedin": {"name": "LinkedIn", "domains": {"linkedin.com"}},
    "twitter": {"name": "Twitter / X", "domains": {"twitter.com", "x.com"}},
    "dropbox": {"name": "Dropbox", "domains": {"dropbox.com"}},
    "adobe": {"name": "Adobe", "domains": {"adobe.com"}},
    "ebay": {"name": "eBay", "domains": {"ebay.com"}},
    "coinbase": {"name": "Coinbase", "domains": {"coinbase.com"}},
    "binance": {"name": "Binance", "domains": {"binance.com"}},
    "fedex": {"name": "FedEx", "domains": {"fedex.com"}},
    "dhl": {"name": "DHL", "domains": {"dhl.com"}},
    # Banking & payments
    "chase": {"name": "Chase Bank", "domains": {"chase.com"}},
    "wellsfargo": {"name": "Wells Fargo", "domains": {"wellsfargo.com"}},
    "bankofamerica": {"name": "Bank of America", "domains": {"bankofamerica.com"}},
    "citibank": {"name": "Citibank", "domains": {"citibank.com", "citi.com"}},
    "hsbc": {"name": "HSBC", "domains": {"hsbc.com", "hsbc.co.in", "hsbc.co.uk"}},
    "barclays": {"name": "Barclays", "domains": {"barclays.com", "barclays.co.uk"}},
    "hdfcbank": {"name": "HDFC Bank", "domains": {"hdfcbank.com"}},
    "icicibank": {"name": "ICICI Bank", "domains": {"icicibank.com"}},
    "axisbank": {"name": "Axis Bank", "domains": {"axisbank.com"}},
    "sbi": {"name": "State Bank of India", "domains": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"}},
    "paytm": {"name": "Paytm", "domains": {"paytm.com"}},
    "phonepe": {"name": "PhonePe", "domains": {"phonepe.com"}},
}

# Brands shorter than this are only matched as a whole hyphen-separated token
SUBSTRING_MIN_LEN = 6
# Brands shorter than this are not compared with edit distance (too many false positives)
EDIT_DISTANCE_MIN_LEN = 6

LEET_MAP = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "!": "i", "|": "l"}

HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
DANGEROUS_SCHEME_RE = re.compile(r"^\s*(javascript|data|vbscript|file|ftp|mailto|blob):", re.I)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "pass": -1}

SAMPLE_URLS = {
    "✅ Safe URL": "https://www.google.com",
    "🎣 Suspicious Phishing URL": "http://paypa1-verify-account.xyz/secure/login.php?session=ZXhhbXBsZQ&redirect=update",
    "🔗 Shortened URL": "https://bit.ly/3xYzAbC",
}

# ----------------------------------------------------------------------------
# GENERIC HELPERS
# ----------------------------------------------------------------------------


def utc_now():
    return datetime.now(timezone.utc)


def make_finding(rid, category, title, triggered, points, severity, detail, tag=""):
    """Create a uniform finding dictionary used by the UI, score engine and report."""
    return {
        "rid": rid,
        "category": category,
        "title": f"{tag}{title}",
        "triggered": bool(triggered),
        "points": int(points) if triggered else 0,
        "severity": severity if triggered else "pass",
        "detail": detail,
    }


def levenshtein(a, b):
    """Optimal-string-alignment distance (Levenshtein + adjacent transposition)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def defang(url):
    """Make a URL safe to paste into reports (prevents accidental clicks)."""
    return url.replace("http", "hxxp").replace(".", "[.]")


def detect_ip(host):
    """
    Return (normalized_ip_string, is_obfuscated) if host is an IP address in any
    common notation (dotted, decimal integer, hex integer, octal/hex dotted); else (None, False).
    """
    try:
        return str(ipaddress.ip_address(host)), False
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d{8,10}", host):
            n = int(host)
            if n < 2 ** 32:
                return str(ipaddress.IPv4Address(n)), True
        if re.fullmatch(r"0x[0-9a-f]{1,8}", host):
            return str(ipaddress.IPv4Address(int(host, 16))), True
        parts = host.split(".")
        if len(parts) == 4 and all(re.fullmatch(r"(0x[0-9a-f]+|\d+)", p) for p in parts):
            nums, odd = [], False
            for p in parts:
                if p.startswith("0x"):
                    nums.append(int(p, 16))
                    odd = True
                elif len(p) > 1 and p.startswith("0"):
                    nums.append(int(p, 8))
                    odd = True
                else:
                    nums.append(int(p))
            if all(0 <= n <= 255 for n in nums) and odd:
                return ".".join(str(n) for n in nums), True
    except (ValueError, ipaddress.AddressValueError):
        pass
    return None, False


def split_domain(host):
    """Return (registered_domain, second_level_label, subdomain, tld) using a light public-suffix heuristic."""
    labels = host.split(".")
    tld = labels[-1] if labels else ""
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:]), labels[-3], ".".join(labels[:-3]), ".".join(labels[-2:])
    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[-2], ".".join(labels[:-2]), tld
    return host, host, "", tld


# ----------------------------------------------------------------------------
# URL PARSING & VALIDATION
# ----------------------------------------------------------------------------


def parse_url(raw):
    """
    Validate and decompose a URL. Returns (info_dict, None) on success or (None, error_message).
    Missing schemes are tolerated: https:// is assumed and the fact is recorded.
    """
    raw = (raw or "").strip()
    if not raw:
        return None, "Please enter a URL or domain to analyze."
    if len(raw) > 2048:
        return None, "Input is longer than 2048 characters and was rejected as invalid."
    if re.search(r"\s", raw):
        return None, "The URL contains whitespace characters and is not a valid URL."
    if DANGEROUS_SCHEME_RE.match(raw):
        return None, ("Unsupported or dangerous URL scheme detected (e.g. javascript:, data:, file:). "
                      "Only http:// and https:// URLs can be analyzed.")

    assumed_scheme = False
    url = raw
    if "://" not in raw:
        url = "https://" + raw.lstrip("/")
        assumed_scheme = True

    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        return None, f"Malformed URL: {exc}"

    if parsed.scheme.lower() not in ("http", "https"):
        return None, f"Unsupported scheme '{parsed.scheme}'. Only http:// and https:// are supported."
    if not host:
        return None, "Could not extract a hostname from the URL."

    host = host.lower().rstrip(".")
    unicode_host = False
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        unicode_host = True
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None, "The hostname contains characters that cannot be encoded as a valid domain name."

    ip_value, ip_obfuscated = detect_ip(host)
    is_ip = ip_value is not None

    if not is_ip:
        if len(host) > 253:
            return None, "Hostname exceeds the maximum length of 253 characters."
        if "." not in host:
            return None, f"'{host}' is not a fully-qualified domain name (no TLD found)."
        labels = host.split(".")
        for lab in labels:
            if not HOST_LABEL_RE.match(lab):
                return None, f"Invalid hostname label '{lab}'. Domain labels may only contain letters, digits and hyphens."
        if labels[-1].isdigit():
            return None, "Invalid hostname: the top-level domain cannot be numeric (malformed IP address?)."

    reg_domain, sld, subdomain, tld = (host, host, "", "") if is_ip else split_domain(host)

    return {
        "original": raw,
        "url": url,
        "scheme": parsed.scheme.lower(),
        "assumed_scheme": assumed_scheme,
        "netloc": parsed.netloc,
        "host": host,
        "port": port,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "is_ip": is_ip,
        "ip_value": ip_value,
        "ip_obfuscated": ip_obfuscated,
        "unicode_host": unicode_host,
        "reg_domain": reg_domain,
        "sld": sld,
        "subdomain": subdomain,
        "tld": tld,
    }, None


# ----------------------------------------------------------------------------
# HEURISTIC / STRUCTURAL ANALYSIS
# ----------------------------------------------------------------------------


def structural_checks(info, tag="", trusted=False, skip_shortener=False):
    """Run all structural heuristics. `trusted` suppresses keyword noise on official brand domains."""
    out = []
    url, host = info["url"], info["host"]
    cat = "Structure"

    def add(rid, title, trig, pts, sev, fail_detail, ok_detail):
        out.append(make_finding(rid, cat, title, trig, pts, sev, fail_detail if trig else ok_detail, tag=tag))

    # 1. IP address instead of domain
    if info["is_ip"]:
        obf = " The address is written in an obfuscated notation (decimal/hex/octal)." if info["ip_obfuscated"] else ""
        add("ip_host", "IP address used instead of a domain name", True, 35 if info["ip_obfuscated"] else 30, "high",
            f"The host is the raw IP `{info['ip_value']}`. Legitimate services almost always use domain names.{obf}", "")
    else:
        add("ip_host", "IP address used instead of a domain name", False, 0, "high", "",
            "The URL uses a domain name rather than a raw IP address.")

    # 2. '@' symbol
    at_in_netloc = "@" in info["netloc"]
    at_anywhere = "@" in url
    add("at_symbol", "'@' symbol in URL", at_anywhere, 25 if at_in_netloc else 8, "critical" if at_in_netloc else "low",
        (f"Everything before '@' is treated as user-info and ignored by the browser; the real destination is `{host}`. "
         "This is a classic trick to disguise a malicious link as a trusted one.") if at_in_netloc
        else "An '@' character appears in the path or query string, which is unusual for legitimate links.",
        "No '@' symbol found in the URL.")

    # 3. Excessive hyphens
    hyphens = host.count("-")
    add("hyphens", "Excessive hyphens in hostname", hyphens >= 3, 8, "medium",
        f"The hostname contains {hyphens} hyphens. Phishing domains often chain words (e.g. `secure-login-verify-account`).",
        f"Hyphen count in hostname is normal ({hyphens}).")

    # 4. Excessive dots / subdomain depth
    dots = host.count(".") if not info["is_ip"] else 0
    add("dots", "Excessive dots / deep subdomain nesting", dots >= 4, 8, "medium",
        f"The hostname contains {dots} dots (deep subdomain nesting) which is often used to bury the real domain.",
        f"Dot count in hostname is normal ({dots}).")

    # 5. Suspicious double slash
    after_scheme = url.split("://", 1)[1] if "://" in url else url
    add("double_slash", "Suspicious double slash '//' in URL", "//" in after_scheme, 10, "medium",
        "A '//' sequence appears after the protocol, a pattern used in redirect tricks and path obfuscation.",
        "No suspicious '//' sequences after the protocol.")

    # 6. Embedded URL / open-redirect parameter
    embedded = re.search(r"https?(://|%3a%2f%2f)", after_scheme, re.I) is not None
    add("embedded_url", "Embedded URL / redirect parameter", embedded, 8, "medium",
        "Another URL is embedded inside this one, commonly used for open-redirect abuse and credential harvesting hops.",
        "No embedded URLs detected.")

    # 7. Suspicious TLD
    tld_last = info["host"].split(".")[-1] if not info["is_ip"] else ""
    add("risky_tld", "Suspicious / high-abuse TLD", (not info["is_ip"]) and tld_last in SUSPICIOUS_TLDS, 15, "high",
        f"The TLD `.{tld_last}` is frequently abused for phishing and malware because of cheap or free registration.",
        f"TLD `.{tld_last}` is not on the high-abuse list." if tld_last else "No TLD to evaluate (IP host).")

    # 8. URL length
    length = len(url)
    add("long_url", "Abnormally long URL", length > 75, 12 if length > 150 else 8, "medium",
        f"The URL is {length} characters long (threshold: 75). Long URLs are used to hide the real domain and payload.",
        f"URL length is within the normal range ({length} characters).")

    # 9. URL shortener
    is_short = (host in URL_SHORTENERS or info["reg_domain"] in URL_SHORTENERS) and not skip_shortener
    if not skip_shortener:
        add("shortener", "URL shortening service", is_short, 12, "medium",
            f"`{info['reg_domain']}` is a URL shortener. The real destination is hidden until the link is followed.",
            "The URL does not use a known link shortener.")

    # 10. Phishing keywords
    host_hits = [k for k in PHISHING_KEYWORDS if k in host] if not trusted else []
    path_hits = [k for k in PHISHING_KEYWORDS if k in (info["path"] + " " + info["query"]).lower()] if not trusted else []
    kw_trig = bool(host_hits or path_hits)
    kw_detail = ""
    if host_hits:
        kw_detail += "Hostname contains: " + ", ".join(f"`{k}`" for k in host_hits) + ". "
    if path_hits:
        kw_detail += "Path/query contains: " + ", ".join(f"`{k}`" for k in path_hits) + "."
    add("keywords", "Credential-bait keywords", kw_trig, 10 if host_hits else 4, "medium" if host_hits else "low",
        kw_detail.strip(), "No credential-bait keywords detected.")

    # 11. Punycode / IDN homograph
    puny = ("xn--" in host) or info["unicode_host"]
    add("punycode", "Punycode / internationalised domain (homograph risk)", puny, 15, "high",
        "The hostname uses IDN/punycode (`xn--`). Attackers use look-alike Unicode characters to imitate real brands.",
        "No punycode or non-ASCII characters in the hostname.")

    # 12. Non-standard port
    port = info["port"]
    add("odd_port", "Non-standard port", port not in (None, 80, 443), 5, "low",
        f"The URL specifies port `{port}`. Legitimate websites rarely require explicit non-standard ports.",
        "No unusual port is specified.")

    # 13. Heavy percent-encoding
    pct = url.count("%")
    add("pct_encoding", "Heavy percent-encoding", pct >= 5, 6, "low",
        f"{pct} percent-encoded sequences found. Encoding is often used to evade filters.",
        "Percent-encoding level is normal.")

    return out


# ----------------------------------------------------------------------------
# TYPOSQUATTING & BRAND IMPERSONATION ENGINE
# ----------------------------------------------------------------------------


def normalize_variants(text):
    """Return possible 'de-obfuscated' spellings of a label (leetspeak and homoglyph sequences)."""
    base = "".join(LEET_MAP.get(c, c) for c in text.lower())
    variants = set()
    for v in {base.replace("1", "l"), base.replace("1", "i")}:
        variants.add(v)
        variants.add(v.replace("rn", "m"))
        variants.add(v.replace("vv", "w"))
        variants.add(v.replace("cl", "d"))
    return variants


def brand_in_label(label, brand):
    """True if brand is a hyphen-token of label, or (for long brands) a substring of it."""
    if brand in label.split("-"):
        return True
    return len(brand) >= SUBSTRING_MIN_LEN and brand in label.replace("-", "")


def typosquat_checks(info, tag=""):
    """Returns (findings, official_brand_name_or_None)."""
    cat = "Typosquatting"
    if info["is_ip"]:
        return [make_finding("typosquat", cat, "Brand impersonation check skipped", False, 0, "high",
                             "Host is an IP address; no domain name to compare with brands.", tag=tag)], None

    reg, label, sub = info["reg_domain"], info["sld"].lower(), info["subdomain"].lower()
    path_blob = (info["path"] + "?" + info["query"]).lower()

    for brand in BRANDS.values():
        if reg in brand["domains"]:
            return [make_finding("typosquat", cat, "Domain matches an official brand domain", False, 0, "high",
                                 f"`{reg}` is an official {brand['name']} domain. No impersonation detected.", tag=tag)], brand["name"]

    variants = normalize_variants(label)
    matches = []

    for key, brand in BRANDS.items():
        found = None

        # (a) brand name used verbatim inside the registered domain label
        if brand_in_label(label, key):
            found = (40, "brand_keyword", "Brand name inside unrelated domain",
                     f"The label `{label}` contains `{key}` but `{reg}` is not an official {brand['name']} domain.", "high")

        # (b) look-alike character substitution (g00gle, paypa1, rnicrosoft ...)
        if not found:
            hit = next((v for v in sorted(variants) if brand_in_label(v, key)), None)
            if hit:
                found = (50, "char_substitution", "Character-substitution typosquatting",
                         f"`{label}` normalises to `{hit}`, imitating `{key}` ({brand['name']}) using look-alike characters "
                         f"(0→o, 1→l, 3→e, rn→m ...).", "critical")

        # (c) small edit distance to the brand (googel, gooogle, amazonn ...)
        if not found and len(key) >= EDIT_DISTANCE_MIN_LEN:
            threshold = 1 if len(key) < 9 else 2
            candidates = set()
            for v in variants | {label}:
                candidates.add(v)
                candidates.update(v.split("-"))
            best = None
            for c in candidates:
                if len(c) >= EDIT_DISTANCE_MIN_LEN - 1 and abs(len(c) - len(key)) <= threshold:
                    dist = levenshtein(c, key)
                    if 0 < dist <= threshold and (best is None or dist < best[0]):
                        best = (dist, c)
            if best:
                found = (40, "typo", "Typosquatting (near-match spelling)",
                         f"`{best[1]}` is only {best[0]} edit(s) away from `{key}` ({brand['name']}).", "high")

        # (d) brand in subdomain of an unrelated domain (paypal.com.evil.xyz)
        if not found and sub:
            for sl in sub.split("."):
                if brand_in_label(sl, key) or any(brand_in_label(v, key) for v in normalize_variants(sl)):
                    found = (35, "brand_subdomain", "Brand name in subdomain of unrelated domain",
                             f"The subdomain `{sub}` references {brand['name']}, but the real domain is `{reg}`.", "high")
                    break

        # (e) brand only in path/query
        if not found and len(key) >= SUBSTRING_MIN_LEN and key in path_blob:
            found = (6, "brand_path", "Brand name in URL path",
                     f"The path/query mentions `{key}` while the domain `{reg}` is unrelated to {brand['name']}.", "low")

        if found:
            matches.append((found, brand["name"]))

    if not matches:
        return [make_finding("typosquat", cat, "No brand impersonation detected", False, 0, "high",
                             f"The domain was compared with {len(BRANDS)} monitored brands (incl. banking) using substring, "
                             "character-substitution and edit-distance analysis. No impersonation found.", tag=tag)], None

    matches.sort(key=lambda m: m[0][0], reverse=True)
    findings = []
    for idx, ((pts, kind, title, detail, sev), name) in enumerate(matches[:4]):
        # Only the strongest match adds to the score; others are shown for context
        findings.append(make_finding("typosquat", cat, f"{title} — {name}", True, pts if idx == 0 else 0, sev, detail, tag=tag))
    return findings, None


# ----------------------------------------------------------------------------
# NETWORK HELPERS (DNS, REDIRECTS, SSL)
# ----------------------------------------------------------------------------


def network_available():
    """Quick connectivity probe so that an offline machine does not flag every URL as broken."""
    try:
        socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
        return True
    except (socket.gaierror, OSError):
        return False


def is_public_host(host):
    """SSRF guard: True only if every resolved address is globally routable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    for item in infos:
        try:
            addr = ipaddress.ip_address(item[4][0].split("%")[0])
        except ValueError:
            return False
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
            return False
    return True


def resolve_redirects(url, timeout=6.0, max_hops=8):
    """Follow redirects manually (HEAD-less GET, body never downloaded) and return the chain."""
    result = {"enabled": True, "hops": [], "final_url": url, "error": None, "blocked": False, "note": None}
    headers = {"User-Agent": "Mozilla/5.0 (PhishingAnalyzer/1.0; security-research)"}
    current = url
    session = requests.Session()
    try:
        for _ in range(max_hops + 1):
            parsed = urlparse(current)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                result["error"] = f"Redirect to unsupported target: {current[:120]}"
                break
            if not is_public_host(parsed.hostname):
                result["blocked"] = True
                result["note"] = (f"Request to `{parsed.hostname}` skipped: host is private/loopback/unresolvable "
                                  "(safety guard against internal-network requests).")
                break
            resp = session.get(current, allow_redirects=False, timeout=timeout, stream=True, headers=headers)
            status = resp.status_code
            location = resp.headers.get("Location")
            resp.close()
            result["hops"].append({"url": current, "status": status})
            if 300 <= status < 400 and location:
                current = urljoin(current, location)
                result["final_url"] = current
                continue
            result["final_url"] = current
            break
        else:
            result["error"] = f"Stopped after {max_hops} redirects (possible redirect loop)."
    except requests.exceptions.Timeout:
        result["error"] = f"Request timed out after {timeout:.0f}s while following redirects."
    except requests.exceptions.SSLError as exc:
        result["error"] = f"SSL error while following redirects: {str(exc)[:160]}"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"Connection error while following redirects: {str(exc)[:160]}"
    except requests.exceptions.RequestException as exc:
        result["error"] = f"Request failed: {str(exc)[:160]}"
    finally:
        session.close()
    return result


def _name_to_dict(rdns):
    """Convert ssl.getpeercert() issuer/subject tuples to a flat dict."""
    out = {}
    for rdn in rdns or ():
        for key, value in rdn:
            out[key] = value
    return out


def inspect_ssl(host, port=443, timeout=6.0):
    """Connect to host:port, validate the certificate chain and collect certificate details."""
    res = {
        "checked": True, "status": "error", "valid": False, "error": None,
        "issuer": None, "subject": None, "not_before": None, "not_after": None,
        "days_left": None, "age_days": None, "tls_version": None, "cipher": None,
        "san": [], "fingerprint": None, "serial": None, "host": host, "port": port,
    }
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
                res["tls_version"] = tls.version()
                cipher = tls.cipher()
                res["cipher"] = cipher[0] if cipher else None
        res["fingerprint"] = hashlib.sha256(der).hexdigest() if der else None
        res["issuer"] = _name_to_dict(cert.get("issuer"))
        res["subject"] = _name_to_dict(cert.get("subject"))
        res["serial"] = cert.get("serialNumber")
        res["san"] = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
        nb = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), tz=timezone.utc)
        na = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        res["not_before"], res["not_after"] = nb.isoformat(), na.isoformat()
        now = utc_now()
        res["days_left"] = (na - now).days
        res["age_days"] = (now - nb).days
        if na < now:
            res["status"], res["error"] = "expired", "The certificate has expired."
        elif nb > now:
            res["status"], res["error"] = "not_yet_valid", "The certificate is not yet valid."
        else:
            res["status"], res["valid"] = "valid", True
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        msg = (getattr(exc, "verify_message", "") or str(exc)).lower()
        res["error"] = getattr(exc, "verify_message", None) or str(exc)
        if code == 10 or "expired" in msg:
            res["status"] = "expired"
        elif code == 9 or "not yet valid" in msg:
            res["status"] = "not_yet_valid"
        elif code in (18, 19) or "self-signed" in msg or "self signed" in msg:
            res["status"] = "self_signed"
        elif code in (62, 64) or "hostname" in msg or "ip address mismatch" in msg:
            res["status"] = "hostname_mismatch"
        else:
            res["status"] = "untrusted"
        # Best effort: collect handshake facts from an unverified connection
        try:
            weak = ssl.create_default_context()
            weak.check_hostname = False
            weak.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with weak.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    res["tls_version"] = tls.version()
                    cipher = tls.cipher()
                    res["cipher"] = cipher[0] if cipher else None
                    res["fingerprint"] = hashlib.sha256(der).hexdigest() if der else None
        except (OSError, ssl.SSLError):
            pass
    except ssl.SSLError as exc:
        res["status"], res["error"] = "no_tls", f"TLS handshake failed: {exc.reason or exc}"
    except socket.timeout:
        res["status"], res["error"] = "timeout", f"Connection to {host}:{port} timed out after {timeout:.0f}s."
    except socket.gaierror as exc:
        res["status"], res["error"] = "dns_error", f"DNS resolution failed: {exc}"
    except ConnectionRefusedError:
        res["status"], res["error"] = "no_tls", f"Connection refused on port {port}: no HTTPS service is listening."
    except OSError as exc:
        res["status"], res["error"] = "error", f"Network error: {exc}"
    except (KeyError, ValueError) as exc:
        res["status"], res["error"] = "error", f"Could not parse certificate: {exc}"
    return res


def ssl_checks(ssl_res, scheme, tag="", trusted=False):
    """Convert SSL inspection results into findings."""
    cat = "SSL/TLS"
    out = []

    def add(rid, title, trig, pts, sev, fail_detail, ok_detail=""):
        out.append(make_finding(rid, cat, title, trig, pts, sev, fail_detail if trig else ok_detail, tag=tag))

    if scheme == "http":
        add("no_https", "Unencrypted HTTP connection (no SSL/TLS)", True, 15, "high",
            "The URL uses plain HTTP. Traffic, including any passwords typed into the page, can be read or modified in transit.")
        return out
    if not ssl_res or not ssl_res.get("checked"):
        return out

    status = ssl_res["status"]
    add("ssl_expired", "SSL certificate expired", status == "expired", 40, "critical",
        f"The certificate expired ({ssl_res.get('not_after', 'unknown')}). Legitimate sites keep certificates current.", "Certificate is not expired.")
    add("ssl_not_yet_valid", "SSL certificate not yet valid", status == "not_yet_valid", 30, "high",
        "The certificate's validity period has not started yet.", "")
    add("ssl_self_signed", "Self-signed certificate", status == "self_signed", 30, "high",
        "The certificate is self-signed and not issued by a trusted Certificate Authority.", "")
    add("ssl_mismatch", "Certificate does not match hostname", status == "hostname_mismatch", 30, "high",
        "The certificate was issued for a different domain than the one being visited, which is a strong indicator of impersonation or interception.", "")
    add("ssl_untrusted", "Untrusted certificate chain", status == "untrusted", 25, "high",
        f"The certificate chain could not be validated: {ssl_res.get('error')}", "")
    add("ssl_missing", "No SSL/TLS service available", status == "no_tls", 20, "high",
        f"{ssl_res.get('error')}. The site does not offer a working HTTPS endpoint.", "")
    add("ssl_unreachable", "SSL inspection could not complete", status in ("timeout", "error"), 5, "low",
        f"{ssl_res.get('error')}", "")

    if status == "valid":
        dl = ssl_res.get("days_left")
        add("ssl_expiring", "Certificate expires very soon", dl is not None and dl < 15, 6, "low",
            f"The certificate expires in {dl} day(s).", f"Certificate valid for another {dl} day(s).")
        age = ssl_res.get("age_days")
        add("ssl_new", "Certificate issued very recently", (not trusted) and age is not None and age < 7, 4, "low",
            f"The certificate was issued only {age} day(s) ago. Phishing sites commonly use freshly issued certificates.",
            f"Certificate age is {age} day(s).")
    return out


# ----------------------------------------------------------------------------
# RISK SCORE ENGINE
# ----------------------------------------------------------------------------


def classify(score):
    if score <= 30:
        return "LOW", "LOW RISK / SAFE"
    if score <= 60:
        return "MEDIUM", "MEDIUM RISK"
    return "HIGH", "HIGH RISK / PHISHING"


def build_recommendations(result):
    """Custom advice driven by the triggered findings plus a verdict-level baseline."""
    triggered = {f["rid"] for f in result["findings"] if f["triggered"]}
    level = result["level"]
    recs = []

    if level == "HIGH":
        recs += [
            "🚫 **Do not visit this site, and do not enter passwords, OTPs, card numbers or sensitive banking details.**",
            "📣 Report the link to your IT/security team, your bank (if a bank is impersonated) and to Google Safe Browsing / PhishTank.",
            "🔑 If you already entered credentials: change that password immediately, enable MFA, and review account activity.",
        ]
    elif level == "MEDIUM":
        recs += [
            "⚠️ **Treat this link with caution.** Do not log in or download files until the destination is verified through another channel.",
            "🔍 Open the official website by typing its address manually or using a trusted bookmark instead of this link.",
        ]
    else:
        recs += [
            "✅ No major phishing indicators were found, but no automated check is perfect. Stay alert for unexpected login prompts.",
            "🔒 Always verify the padlock, the exact domain spelling and the context of the message that delivered the link.",
        ]

    mapping = {
        "ip_host": "🌐 Never trust links that point to a raw IP address; legitimate brands use their own domain names.",
        "at_symbol": "✂️ The text before '@' is ignored by the browser. Check only the domain that follows the '@'.",
        "hyphens": "🔤 Be suspicious of long hyphenated domains such as `secure-login-account-verify`; read the domain from right to left.",
        "dots": "🧅 Deeply nested subdomains hide the real domain. Focus on the last two labels before the first '/'.",
        "double_slash": "🔀 Unexpected '//' sequences can hide redirects. Avoid following the link; type the official address instead.",
        "embedded_url": "↪️ Embedded redirect parameters can bounce you to attacker pages. Do not trust the visible first domain alone.",
        "risky_tld": "🚩 The TLD is frequently abused. Be extra careful with sensitive actions on such domains.",
        "long_url": "📏 Very long URLs hide the destination. Expand/inspect the full address before clicking.",
        "shortener": "🔗 Preview shortened links with a URL expander before opening, and avoid them in unsolicited messages.",
        "keywords": "🎣 Urgent 'verify / secure / suspend' wording is classic social-engineering bait. Contact the company via official channels.",
        "punycode": "🔠 Look-alike (IDN) characters can mimic real brands. Use bookmarks or type the official domain yourself.",
        "odd_port": "🔌 Unusual ports are uncommon for consumer sites; verify the link source.",
        "pct_encoding": "🧬 Heavy URL encoding can evade filters; inspect the decoded URL before proceeding.",
        "typosquat": "🧐 The domain imitates a known brand. Compare it character-by-character with the official site, and report it to the brand's abuse team.",
        "no_https": "🔓 The page is not encrypted. Never submit credentials over plain HTTP.",
        "ssl_expired": "📅 An expired certificate means the site is neglected or malicious; browsers will warn you. Do not click through the warning.",
        "ssl_not_yet_valid": "📅 The certificate is not valid yet, which indicates a misconfigured or forged setup. Do not proceed.",
        "ssl_self_signed": "🪪 Self-signed certificates provide no identity assurance. Do not proceed to enter data.",
        "ssl_mismatch": "🕵️ The certificate belongs to another domain, which may indicate impersonation or traffic interception.",
        "ssl_untrusted": "⛓️ The certificate chain is not trusted. Do not bypass the browser warning.",
        "ssl_missing": "🔐 The site offers no working HTTPS. Avoid sharing any information with it.",
        "ssl_new": "🆕 Freshly issued certificates are common on throw-away phishing sites; combine with other indicators.",
        "ssl_expiring": "⏳ The certificate is close to expiry; this alone is not malicious but suggests poor maintenance.",
        "redirect_cross": "🔁 The link redirects to a different domain. Evaluate the final destination, not the first hop.",
        "dns_fail": "🛰️ The domain does not resolve, the site may be taken down or not yet live. Do not rely on it.",
    }
    for rid, text in mapping.items():
        if rid in triggered:
            recs.append(text)

    recs.append("🛡️ General hygiene: enable multi-factor authentication, keep browsers updated, and use a password manager "
                "(it will not autofill on look-alike domains).")
    return recs


def analyze(raw, follow_redirects=True, timeout=6.0):
    """Full analysis pipeline. Always returns a result dict (with 'error' set on invalid input)."""
    result = {
        "input": (raw or "").strip(),
        "timestamp": utc_now().isoformat(timespec="seconds"),
        "error": None, "info": None, "final_info": None, "findings": [], "ssl": None,
        "redirect": None, "online": None, "score": 0, "level": "LOW", "verdict": "LOW RISK / SAFE",
        "category_scores": {}, "recommendations": [], "notes": [], "official_brand": None,
    }
    info, err = parse_url(raw)
    if err:
        result["error"] = err
        return result
    result["info"] = info
    findings = []

    if info["assumed_scheme"]:
        result["notes"].append("No protocol was supplied, so `https://` was assumed for the analysis.")

    # --- Typosquatting first (so that official brand domains suppress keyword noise) ---
    typo_findings, official = typosquat_checks(info)
    result["official_brand"] = official
    findings += structural_checks(info, trusted=bool(official))
    findings += typo_findings

    # --- Network-dependent checks ---
    online = network_available()
    result["online"] = online
    target = info
    if not online:
        result["notes"].append("Network unavailable: DNS, redirect and SSL/TLS live checks were skipped. Only static analysis was performed.")
    else:
        if follow_redirects:
            red = resolve_redirects(info["url"], timeout=timeout)
            result["redirect"] = red
            if red.get("note"):
                result["notes"].append(red["note"])
            final_url = red.get("final_url")
            if final_url and final_url != info["url"]:
                final_info, ferr = parse_url(final_url)
                if final_info:
                    result["final_info"] = final_info
                    cross = final_info["reg_domain"] != info["reg_domain"]
                    shortener = info["host"] in URL_SHORTENERS or info["reg_domain"] in URL_SHORTENERS
                    findings.append(make_finding(
                        "redirect_cross", "Redirect", "Redirects to a different domain",
                        cross, 0 if shortener else 10, "medium",
                        f"The link redirects ({len(red['hops'])} hop(s)) to `{final_info['host']}`"
                        + (" (expected for a shortener, destination analysed below)." if shortener else "."),
                        "The final destination uses the same registered domain."))
                    if cross or final_info["host"] != info["host"]:
                        f_typo, f_official = typosquat_checks(final_info, tag="Redirect target: ")
                        findings += structural_checks(final_info, tag="Redirect target: ", trusted=bool(f_official), skip_shortener=True)
                        findings += f_typo
                        target = final_info
                        if f_official and not official:
                            result["official_brand"] = f_official
            if red.get("error"):
                result["notes"].append(red["error"])

        # DNS resolution of the effective target
        if not target["is_ip"]:
            try:
                socket.getaddrinfo(target["host"], None)
                findings.append(make_finding("dns_fail", "Network", "Domain resolves in DNS", False, 0, "medium", "", tag=""))
                findings[-1]["detail"] = f"`{target['host']}` resolves to an IP address."
            except (socket.gaierror, OSError):
                findings.append(make_finding("dns_fail", "Network", "Domain does not resolve in DNS", True, 10, "medium",
                                             f"`{target['host']}` could not be resolved. The site may be dead, newly burned or mistyped."))

        # SSL/TLS
        if target["scheme"] == "https":
            port = target["port"] or 443
            result["ssl"] = inspect_ssl(target["host"], port=port, timeout=timeout)
            findings += ssl_checks(result["ssl"], "https", trusted=bool(result["official_brand"]))
        else:
            result["ssl"] = {"checked": False, "status": "skipped", "valid": False,
                             "error": "The URL uses HTTP; there is no certificate to inspect."}
            findings += ssl_checks(result["ssl"], "http")

    if not online and info["scheme"] == "http":
        findings += ssl_checks(None, "http")

    # --- Scoring ---
    cat_scores = {}
    for f in findings:
        cat_scores[f["category"]] = cat_scores.get(f["category"], 0) + f["points"]
    total = min(100, sum(cat_scores.values()))
    level, verdict = classify(total)
    result.update({"findings": findings, "category_scores": cat_scores, "score": total, "level": level, "verdict": verdict})
    result["recommendations"] = build_recommendations(result)
    return result


# ----------------------------------------------------------------------------
# REPORT GENERATION
# ----------------------------------------------------------------------------


def build_report(result):
    info = result["info"]
    lines = []
    lines.append(f"# Phishing Analysis Report")
    lines.append(f"_Generated by {APP_NAME} v{APP_VERSION}_\n")
    lines.append(f"- **Analysis time (UTC):** {result['timestamp']}")
    lines.append(f"- **Analyzed URL (defanged):** `{defang(result['input'])}`")
    if info:
        lines.append(f"- **Normalized URL (defanged):** `{defang(info['url'])}`")
        lines.append(f"- **Host:** `{info['host']}`  |  **Registered domain:** `{info['reg_domain']}`")
    final = result.get("final_info")
    if final:
        lines.append(f"- **Final redirect destination (defanged):** `{defang(final['url'])}`")
    lines.append("")
    lines.append("## Final Verdict")
    lines.append(f"- **Risk score:** {result['score']}%")
    lines.append(f"- **Risk level:** {result['verdict']}")
    if result.get("official_brand"):
        lines.append(f"- **Note:** domain matches an official {result['official_brand']} domain.")
    lines.append("")
    lines.append("## Score Breakdown by Category")
    for cat, pts in result["category_scores"].items():
        lines.append(f"- {cat}: +{pts}")
    lines.append("")
    triggered = sorted([f for f in result["findings"] if f["triggered"]], key=lambda f: -SEVERITY_ORDER.get(f["severity"], 0))
    lines.append(f"## Detected Anomalies ({len(triggered)})")
    if triggered:
        for f in triggered:
            lines.append(f"- **[{f['severity'].upper()}] {f['title']}** (+{f['points']}) — {f['category']}")
            lines.append(f"  - {f['detail']}")
    else:
        lines.append("- No anomalies detected.")
    lines.append("")
    passed = [f for f in result["findings"] if not f["triggered"]]
    lines.append(f"## Checks Passed ({len(passed)})")
    for f in passed:
        lines.append(f"- {f['title']}")
    lines.append("")
    lines.append("## SSL/TLS Inspection")
    s = result.get("ssl")
    if s and s.get("checked"):
        issuer = s.get("issuer") or {}
        subject = s.get("subject") or {}
        lines.append(f"- Status: **{s['status'].upper()}**")
        if s.get("error"):
            lines.append(f"- Detail: {s['error']}")
        lines.append(f"- Issuer: {issuer.get('organizationName', issuer.get('commonName', 'n/a'))}")
        lines.append(f"- Subject CN: {subject.get('commonName', 'n/a')}")
        lines.append(f"- Valid from: {s.get('not_before') or 'n/a'}")
        lines.append(f"- Expires: {s.get('not_after') or 'n/a'} (days left: {s.get('days_left') if s.get('days_left') is not None else 'n/a'})")
        lines.append(f"- TLS version / cipher: {s.get('tls_version') or 'n/a'} / {s.get('cipher') or 'n/a'}")
        lines.append(f"- SHA-256 fingerprint: {s.get('fingerprint') or 'n/a'}")
    elif s:
        lines.append(f"- {s.get('error', 'Not performed.')}")
    else:
        lines.append("- Not performed (network unavailable).")
    lines.append("")
    red = result.get("redirect")
    if red and red.get("hops"):
        lines.append("## Redirect Chain")
        for i, hop in enumerate(red["hops"], 1):
            lines.append(f"{i}. `{defang(hop['url'])}` → HTTP {hop['status']}")
        lines.append("")
    if result["notes"]:
        lines.append("## Analysis Notes")
        for n in result["notes"]:
            lines.append(f"- {n.replace('`', '')}")
        lines.append("")
    lines.append("## Security Recommendations")
    for r in result["recommendations"]:
        lines.append(f"- {r.replace('**', '')}")
    lines.append("")
    lines.append("## Disclaimer")
    lines.append("This automated report is based on heuristics and live network checks. It is an aid to human judgement, "
                 "not a guarantee of safety or maliciousness. URLs in this report are defanged for safe handling.")
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# STREAMLIT UI
# ----------------------------------------------------------------------------

CUSTOM_CSS = """
<style>
.stApp { background: radial-gradient(circle at 20% 0%, #101a2e 0%, #0a0e17 55%); color: #d6e2f5; }
[data-testid="stSidebar"] { background: #0c1220; border-right: 1px solid #1d2a44; }
h1, h2, h3 { color: #e8f1ff; letter-spacing: .3px; }
.hero { padding: 18px 24px; border: 1px solid #1f3a5f; border-radius: 14px;
        background: linear-gradient(135deg, #0e1b33 0%, #0a1426 100%); margin-bottom: 14px; }
.hero h1 { margin: 0; font-size: 1.9rem; }
.hero p { margin: 4px 0 0; color: #7f93b5; font-size: .95rem; }
.banner { padding: 22px 26px; border-radius: 14px; margin: 10px 0 18px; border: 1px solid; }
.banner .big { font-size: 1.7rem; font-weight: 800; letter-spacing: .5px; }
.banner .sub { font-size: .95rem; opacity: .92; margin-top: 4px; word-break: break-all; }
.banner.safe   { background: rgba(0,200,120,.10); border-color: #00c878; color: #7dffc1; }
.banner.warn   { background: rgba(255,196,0,.10); border-color: #ffc400; color: #ffe27a; }
.banner.danger { background: rgba(255,50,70,.14); border-color: #ff3246; color: #ff9aa6;
                 box-shadow: 0 0 24px rgba(255,50,70,.25); }
[data-testid="stMetric"] { background: #0e1729; border: 1px solid #1c2c4a; border-radius: 12px; padding: 12px 16px; }
.stButton > button { border-radius: 10px; border: 1px solid #2a4570; }
.small-muted { color: #7f93b5; font-size: .85rem; }
</style>
"""


def set_sample(url):
    st.session_state["url_input"] = url
    st.session_state["auto_run"] = True


def render_finding(f):
    label = f"**{f['title']}**  ·  `+{f['points']} pts`  ·  _{f['category']}_\n\n{f['detail']}"
    sev = f["severity"]
    if sev in ("critical", "high"):
        st.error(label, icon="🚨")
    elif sev == "medium":
        st.warning(label, icon="⚠️")
    else:
        st.info(label, icon="ℹ️")


def render_findings(findings, categories):
    subset = [f for f in findings if f["category"] in categories]
    triggered = sorted([f for f in subset if f["triggered"]], key=lambda f: -SEVERITY_ORDER.get(f["severity"], 0))
    passed = [f for f in subset if not f["triggered"]]
    if triggered:
        for f in triggered:
            render_finding(f)
    else:
        st.success("No anomalies detected in this category.", icon="✅")
    if passed:
        with st.expander(f"Passed checks ({len(passed)})"):
            for f in passed:
                st.markdown(f"✅ **{f['title']}** — {f['detail']}")


def render_banner(result):
    cls = {"LOW": "safe", "MEDIUM": "warn", "HIGH": "danger"}[result["level"]]
    icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}[result["level"]]
    headline = {"LOW": "LOW RISK / SAFE", "MEDIUM": "MEDIUM RISK — PROCEED WITH CAUTION",
                "HIGH": "HIGH RISK — LIKELY PHISHING"}[result["level"]]
    target = html.escape(result["info"]["url"][:200])
    st.markdown(
        f'<div class="banner {cls}"><div class="big">{icon} {headline} &nbsp;·&nbsp; {result["score"]}%</div>'
        f'<div class="sub">{target}</div></div>', unsafe_allow_html=True)


def render_overview(result):
    info = result["info"]
    ssl_res = result.get("ssl") or {}
    triggered = [f for f in result["findings"] if f["triggered"]]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Phishing Risk Score", f"{result['score']}%")
    c2.metric("Risk Level", result["level"])
    c3.metric("Flags Triggered", f"{len(triggered)} / {len(result['findings'])}")
    ssl_label = {"valid": "Valid", "skipped": "No HTTPS"}.get(ssl_res.get("status"), (ssl_res.get("status") or "n/a").replace("_", " ").title())
    c4.metric("SSL/TLS Status", ssl_label)
    st.progress(min(result["score"], 100) / 100.0, text=f"Overall risk: {result['score']}%")

    st.markdown("##### Score contribution by module")
    cats = ["Structure", "Typosquatting", "SSL/TLS", "Network", "Redirect"]
    cols = st.columns(len(cats))
    for col, cat in zip(cols, cats):
        pts = result["category_scores"].get(cat, 0)
        col.metric(cat, f"+{pts}")

    if result.get("official_brand"):
        st.success(f"The registered domain matches an official **{result['official_brand']}** domain.", icon="🏷️")
    for note in result["notes"]:
        st.info(note, icon="📝")

    left, right = st.columns(2)
    with left:
        st.markdown("##### URL anatomy")
        st.json({
            "scheme": info["scheme"] + (" (assumed)" if info["assumed_scheme"] else ""),
            "host": info["host"],
            "registered_domain": info["reg_domain"],
            "subdomain": info["subdomain"] or None,
            "tld": info["tld"] or None,
            "port": info["port"],
            "path": info["path"] or "/",
            "query": info["query"] or None,
            "is_ip_host": info["is_ip"],
            "url_length": len(info["url"]),
        })
    with right:
        red = result.get("redirect")
        st.markdown("##### Redirect chain")
        if red and red.get("hops"):
            for i, hop in enumerate(red["hops"], 1):
                st.code(f"{i}. [{hop['status']}] {hop['url']}", language=None)
            if result.get("final_info"):
                st.caption("Final destination: " + result["final_info"]["url"][:160])
        elif red is None:
            st.caption("Redirect resolution disabled or network unavailable.")
        else:
            st.caption("No redirect hops recorded.")


def render_ssl_tab(result):
    s = result.get("ssl")
    if not s:
        st.warning("SSL/TLS inspection was skipped because the network is unavailable.", icon="📡")
        return
    findings = result["findings"]
    if not s.get("checked"):
        st.error("**No SSL/TLS certificate: the URL uses plain HTTP.** All data sent to this site is unencrypted.", icon="🔓")
        render_findings(findings, {"SSL/TLS"})
        return
    status = s["status"]
    if status == "valid":
        st.success(f"A valid, trusted certificate was presented by `{s['host']}`.", icon="🔒")
    elif status == "expired":
        st.error("**EXPIRED CERTIFICATE** — this site presents an expired SSL certificate.", icon="⛔")
    else:
        st.error(f"**Certificate problem ({status.replace('_', ' ')}):** {s.get('error')}", icon="🚨")

    issuer = s.get("issuer") or {}
    subject = s.get("subject") or {}
    if s.get("not_after"):
        c1, c2, c3 = st.columns(3)
        c1.metric("Issuer", issuer.get("organizationName", issuer.get("commonName", "n/a")))
        c2.metric("Expires", s["not_after"][:10])
        c3.metric("Days Remaining", s["days_left"])
        c4, c5, c6 = st.columns(3)
        c4.metric("Valid From", s["not_before"][:10])
        c5.metric("TLS Version", s.get("tls_version") or "n/a")
        c6.metric("Cipher", (s.get("cipher") or "n/a")[:24])
        st.markdown(f"**Subject CN:** `{subject.get('commonName', 'n/a')}`")
        if s.get("san"):
            st.markdown("**Subject Alternative Names:** " + ", ".join(f"`{n}`" for n in s["san"][:12])
                        + (" …" if len(s["san"]) > 12 else ""))
    elif status != "valid":
        st.caption("Certificate fields could not be read because the certificate failed validation.")
        if s.get("tls_version"):
            st.markdown(f"**TLS version:** `{s['tls_version']}`  |  **Cipher:** `{s.get('cipher')}`")
    if s.get("fingerprint"):
        st.markdown("**SHA-256 fingerprint:**")
        st.code(s["fingerprint"], language=None)
    st.markdown("##### SSL/TLS checks")
    render_findings(findings, {"SSL/TLS"})


def render_results(result):
    if result["error"]:
        st.error(f"**Invalid input:** {result['error']}", icon="❌")
        return
    render_banner(result)
    tabs = st.tabs(["📊 Overview", "🧩 URL Heuristics", "🎭 Typosquatting", "🔐 SSL / TLS", "🛡️ Recommendations", "📄 Report"])
    with tabs[0]:
        render_overview(result)
    with tabs[1]:
        st.markdown("#### Structural & Heuristic URL Analysis")
        render_findings(result["findings"], {"Structure", "Network", "Redirect"})
    with tabs[2]:
        st.markdown("#### Typosquatting & Brand Impersonation Engine")
        st.caption(f"Compared against {len(BRANDS)} monitored brands (tech, e-commerce, payments and banking) using substring, "
                   "leetspeak/homoglyph normalisation and edit-distance analysis.")
        render_findings(result["findings"], {"Typosquatting"})
    with tabs[3]:
        render_ssl_tab(result)
    with tabs[4]:
        st.markdown("#### Actionable Security Recommendations")
        for rec in result["recommendations"]:
            st.markdown(f"- {rec}")
    with tabs[5]:
        st.markdown("#### Automated Audit Report")
        report = build_report(result)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        d1, d2 = st.columns(2)
        d1.download_button("⬇️ Download report (.md)", data=report, file_name=f"phishing_report_{stamp}.md",
                           mime="text/markdown", use_container_width=True)
        d2.download_button("⬇️ Download report (.txt)", data=report, file_name=f"phishing_report_{stamp}.txt",
                           mime="text/plain", use_container_width=True)
        with st.expander("Preview report", expanded=True):
            st.markdown(report)
        with st.expander("Raw analysis data (JSON)"):
            st.code(json.dumps(result, indent=2, default=str), language="json")


def main():
    st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    st.session_state.setdefault("url_input", "")
    st.session_state.setdefault("result", None)
    st.session_state.setdefault("history", [])

    # ---- Sidebar ----
    with st.sidebar:
        st.markdown("### ⚙️ Scan Settings")
        follow = st.checkbox("Resolve redirects (contacts target)", value=True,
                             help="Follows the redirect chain with GET requests (page bodies are never downloaded). "
                                  "Requests to private/internal addresses are blocked.")
        timeout = st.slider("Network timeout (seconds)", 2, 20, 6)
        st.markdown("---")
        st.markdown("### 📚 Detection Coverage")
        st.markdown(f"- Monitored brands: **{len(BRANDS)}**\n- High-abuse TLDs: **{len(SUSPICIOUS_TLDS)}**\n"
                    f"- Known shorteners: **{len(URL_SHORTENERS)}**\n- Heuristic checks: **13**")
        st.markdown("---")
        st.markdown("### 🕘 Recent Scans")
        if st.session_state["history"]:
            for item in st.session_state["history"][:8]:
                icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}[item["level"]]
                st.markdown(f"{icon} `{item['score']}%` {html.escape(item['url'][:34])}")
            if st.button("Clear history"):
                st.session_state["history"] = []
                st.rerun()
        else:
            st.caption("No scans yet.")
        st.markdown("---")
        st.caption("This tool provides heuristic guidance only; always verify suspicious links through official channels.")

    # ---- Header ----
    st.markdown(f'<div class="hero"><h1>🛡️ {APP_NAME}</h1>'
                '<p>Heuristic analysis · Typosquatting detection · SSL/TLS inspection · Risk scoring</p></div>',
                unsafe_allow_html=True)

    # ---- Input ----
    st.text_input("Enter a URL or domain to analyze", key="url_input",
                  placeholder="https://example.com/login  or  example.com")
    st.markdown('<span class="small-muted">Quick test samples:</span>', unsafe_allow_html=True)
    cols = st.columns(len(SAMPLE_URLS) + 1)
    for col, (label, url) in zip(cols, SAMPLE_URLS.items()):
        col.button(label, on_click=set_sample, args=(url,), use_container_width=True)
    analyze_clicked = cols[-1].button("🔍 Analyze URL", type="primary", use_container_width=True)

    auto_run = st.session_state.pop("auto_run", False)
    if analyze_clicked or auto_run:
        with st.spinner("Running heuristic, typosquatting and SSL/TLS analysis..."):
            try:
                result = analyze(st.session_state["url_input"], follow_redirects=follow, timeout=float(timeout))
            except Exception as exc:  # last-resort guard so the UI never crashes
                result = {"error": f"Unexpected analysis failure: {exc}"}
        st.session_state["result"] = result
        if not result.get("error"):
            st.session_state["history"].insert(0, {"url": result["input"], "score": result["score"], "level": result["level"]})
            st.session_state["history"] = st.session_state["history"][:20]

    if st.session_state["result"] is not None:
        render_results(st.session_state["result"])
    else:
        st.info("Enter a URL above (or click a sample) and press **Analyze URL** to begin.", icon="👆")


if __name__ == "__main__":
    main()

# ----------------------------------------------------------------------------
# EXECUTION INSTRUCTIONS
# ----------------------------------------------------------------------------
# 1. Install Python 3.9+ and create (optionally) a virtual environment:
#        python -m venv venv
#        source venv/bin/activate          # Windows: venv\Scripts\activate
#
# 2. Install dependencies:
#        pip install streamlit requests
#
# 3. Save this file as  app.py  and run it from the same folder:
#        streamlit run app.py
#
# 4. Open the URL shown in the terminal (default: http://localhost:8501).
#
# Optional - force the dark theme: create  .streamlit/config.toml  containing
#        [theme]
#        base = "dark"
#
# Notes:
#   * SSL/TLS inspection, DNS resolution and redirect resolution need internet access.
#     Offline, the app automatically falls back to static analysis only.
#   * Tick/untick "Resolve redirects" in the sidebar to control whether the target
#     is contacted. Page bodies are never downloaded or rendered.
