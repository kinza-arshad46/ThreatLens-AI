"""
url_scanner.py
--------------
Website / URL Threat Scanner -- a NEW engine, separate from the trained
CICIDS2017 models (Isolation Forest, Random Forest/XGBoost).

Honest design note (important -- read before extending this): the trained
anomaly/classifier models expect NETWORK FLOW features (flow duration,
packet counts, byte rates, ...). A URL string cannot be fed into them --
it isn't the same feature space. This module is a deliberately separate,
purpose-built heuristic scanner for URLs/websites, built to LOOK and FEEL
consistent with the rest of ThreatLens AI (same 0-100 risk score, same
Low/Medium/High/Critical severity labels via threat_score.severity_label),
but its actual signals are specific to URL/website risk, not network flows.

Every check below is a heuristic signal, not a certainty -- a single flag
(e.g. no security headers) does not mean a site is malicious. The combined
score is meant to guide a human reviewer's attention, the same way the
dataset-upload feature's threat score does.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from src.models.threat_score import severity_label

# A short list of well-known URL-shortening services -- a shortened link
# hides the real destination, which is itself a mild risk signal (not
# proof of anything malicious, but worth flagging for a human to check).
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "cutt.ly", "shorte.st",
}

# Keywords that show up disproportionately often in phishing URLs when
# combined with a domain that doesn't match a known brand -- e.g.
# "paypal-login-secure.xyz123.com". Flagging the keyword alone is NOT
# proof of phishing; it's one signal among several.
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "password", "wallet",
]


@dataclass
class URLScanResult:
    url: str
    risk_score: float
    severity: str
    flags: list[dict] = field(default_factory=list)   # [{"signal": "...", "detail": "...", "weight": 0.2}, ...]
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reachable: bool = True
    error: str | None = None


def _check_url_structure(url: str, parsed) -> list[dict]:
    """Checks that need no network call -- pure string/structure analysis."""
    flags = []
    host = parsed.hostname or ""

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        flags.append({"signal": "ip_as_hostname", "detail": f"URL uses a raw IP address ({host}) instead of a domain name.", "weight": 0.25})

    if len(url) > 100:
        flags.append({"signal": "excessive_length", "detail": f"URL is unusually long ({len(url)} characters).", "weight": 0.08})

    if "@" in url:
        flags.append({"signal": "at_symbol", "detail": "URL contains '@', a classic trick to hide the real destination host.", "weight": 0.2})

    if host.count(".") >= 4:
        flags.append({"signal": "excessive_subdomains", "detail": f"Domain has an unusually high number of subdomains ({host}).", "weight": 0.12})

    if host.count("-") >= 3:
        flags.append({"signal": "excessive_hyphens", "detail": "Domain contains an unusually high number of hyphens.", "weight": 0.08})

    if any(host == s or host.endswith("." + s) for s in KNOWN_SHORTENERS):
        flags.append({"signal": "url_shortener", "detail": f"'{host}' is a known URL-shortening service -- the real destination is hidden.", "weight": 0.15})

    matched_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if matched_keywords:
        flags.append({
            "signal": "suspicious_keywords",
            "detail": f"URL contains phishing-associated keyword(s): {', '.join(matched_keywords)}.",
            "weight": min(0.05 * len(matched_keywords), 0.15),
        })

    if parsed.scheme != "https":
        flags.append({"signal": "no_https", "detail": "URL does not use HTTPS.", "weight": 0.2})

    return flags


def _check_ssl_certificate(host: str, timeout: float = 5.0) -> list[dict]:
    """
    Connects to the host on port 443 and inspects its TLS certificate.
    Wrapped so ANY failure here (timeout, no TLS, DNS failure) becomes a
    flag rather than crashing the whole scan -- consistent with how the
    rest of ThreatLens AI degrades gracefully (e.g. the Redis cache
    fallback) instead of failing hard on one unavailable signal.
    """
    flags = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            flags.append({"signal": "cert_expired", "detail": f"TLS certificate expired {abs(days_left)} day(s) ago.", "weight": 0.3})
        elif days_left < 14:
            flags.append({"signal": "cert_expiring_soon", "detail": f"TLS certificate expires in {days_left} day(s).", "weight": 0.1})
    except Exception as e:
        flags.append({"signal": "cert_check_failed", "detail": f"Could not verify TLS certificate ({type(e).__name__}).", "weight": 0.15})
    return flags


def _check_http_response(url: str, timeout: float = 6.0) -> tuple[list[dict], bool, str | None]:
    """
    Makes a real HTTP(S) request: follows redirects, inspects the final
    response's status/headers, and flags an unusually long or
    cross-domain-heavy redirect chain.

    Returns (flags, reachable, error_message). `reachable=False` means the
    site could not be contacted at all -- itself worth surfacing, but not
    treated as automatically "malicious" (plenty of legitimate sites are
    just temporarily down).
    """
    flags = []
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            resp = client.get(url)

        if len(resp.history) >= 3:
            hosts = {urlparse(str(r.url)).hostname for r in resp.history} | {urlparse(str(resp.url)).hostname}
            flags.append({
                "signal": "long_redirect_chain",
                "detail": f"Request redirected {len(resp.history)} times across {len(hosts)} distinct host(s).",
                "weight": 0.15 if len(hosts) > 1 else 0.05,
            })

        security_headers = ["content-security-policy", "x-frame-options", "strict-transport-security"]
        missing = [h for h in security_headers if h not in resp.headers]
        if len(missing) == len(security_headers):
            flags.append({"signal": "no_security_headers", "detail": "None of the common security response headers were present.", "weight": 0.08})

        if resp.status_code >= 400:
            flags.append({"signal": "error_status", "detail": f"Final response returned HTTP {resp.status_code}.", "weight": 0.1})

        return flags, True, None
    except Exception as e:
        return [], False, f"{type(e).__name__}: {e}"


def _check_domain_age(host: str) -> list[dict]:
    """
    Best-effort WHOIS lookup. WHOIS servers vary a lot by registrar and
    frequently rate-limit or time out -- this is treated as a soft signal
    that may simply be unavailable, never a hard failure of the scan.
    """
    flags = []
    try:
        import whois  # imported lazily so a missing/broken install doesn't affect the rest of the scanner
        info = whois.whois(host)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 30:
                flags.append({"signal": "very_new_domain", "detail": f"Domain was registered only {age_days} day(s) ago.", "weight": 0.25})
            elif age_days < 180:
                flags.append({"signal": "new_domain", "detail": f"Domain was registered {age_days} day(s) ago (under 6 months old).", "weight": 0.1})
    except Exception:
        # Silently skipped: WHOIS is a bonus signal, not a required one.
        # A failed lookup does not count against the site being scanned.
        pass
    return flags


def scan_url(url: str) -> URLScanResult:
    """
    Runs the full URL scan pipeline and returns a combined 0-100 risk
    score + severity label, in the same shape as the dataset-upload
    feature's results (see src/ingestion/upload_processor.py) so the
    frontend can present both consistently.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""

    all_flags = _check_url_structure(url, parsed)

    http_flags, reachable, error = _check_http_response(url)
    all_flags.extend(http_flags)

    if reachable:
        all_flags.extend(_check_ssl_certificate(host))
        all_flags.extend(_check_domain_age(host))
    else:
        all_flags.append({"signal": "unreachable", "detail": f"Site could not be reached: {error}", "weight": 0.1})

    total_weight = sum(f["weight"] for f in all_flags)
    risk_score = round(min(total_weight * 100, 100), 1)
    severity = severity_label(risk_score)

    return URLScanResult(
        url=url,
        risk_score=risk_score,
        severity=severity,
        flags=all_flags,
        reachable=reachable,
        error=error,
    )
