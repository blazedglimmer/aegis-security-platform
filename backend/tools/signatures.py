"""Deterministic passive security checks over real HTTP evidence.

These are not LLM guesses and not probabilistic scanner heuristics — each check
reads an actual :class:`Exchange` (request/response captured by the guarded
client) and emits a :class:`Finding` only when the evidence is present in that
exchange. This is what lets Aegis produce reliable, reproducible findings even
with no external scanner installed.

Every finding carries a CVSS vector so the analysis agent can score it by
formula. Vectors here are conservative defaults the analyst can adjust.
"""

from __future__ import annotations

import re

from ..domain import Finding, Severity
from .http_client import Exchange

AGENT = "web_vuln"


def _h(ex: Exchange) -> dict[str, str]:
    return {k.lower(): v for k, v in ex.response_headers.items()}


def _finding(**kw) -> Finding:
    kw.setdefault("agent", AGENT)
    kw.setdefault("confidence", "high")
    return Finding(**kw)


def check_security_headers(ex: Exchange) -> list[Finding]:
    h = _h(ex)
    out: list[Finding] = []
    ctype = h.get("content-type", "")
    is_html = "text/html" in ctype or ctype == ""

    if is_html and "content-security-policy" not in h:
        out.append(_finding(
            title="Missing Content-Security-Policy header",
            severity=Severity.MEDIUM, category="A05:2021-Security Misconfiguration",
            endpoint=ex.url,
            description="The response does not set a Content-Security-Policy, so the "
                        "browser applies no restriction on script/style sources, "
                        "weakening defense-in-depth against XSS and data injection.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            impact="If an injection flaw exists elsewhere, the absence of CSP removes "
                   "a key mitigation that would otherwise limit exploitation.",
            remediation="Add a restrictive Content-Security-Policy (e.g. default-src 'self'; "
                        "object-src 'none'; frame-ancestors 'none') and tighten iteratively.",
            evidence=ex.as_evidence(),
            references=["https://owasp.org/www-project-secure-headers/"],
        ))
    if "strict-transport-security" not in h and ex.url.startswith("https"):
        out.append(_finding(
            title="Missing HTTP Strict-Transport-Security header",
            severity=Severity.LOW, category="A05:2021-Security Misconfiguration",
            endpoint=ex.url,
            description="HSTS is not set, so a user's browser may be downgraded to HTTP "
                        "by a network attacker (SSL stripping) before the first redirect.",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
            impact="Enables man-in-the-middle SSL-stripping on first or unprotected visits.",
            remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains "
                        "(add preload once validated).",
            evidence=ex.as_evidence(),
        ))
    if is_html and "x-content-type-options" not in h:
        out.append(_finding(
            title="Missing X-Content-Type-Options: nosniff",
            severity=Severity.LOW, category="A05:2021-Security Misconfiguration",
            endpoint=ex.url, confidence="high",
            description="Without nosniff, browsers may MIME-sniff responses, enabling some "
                        "content-type confusion attacks.",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            remediation="Add X-Content-Type-Options: nosniff to all responses.",
            evidence=ex.as_evidence(),
        ))
    if is_html and "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        out.append(_finding(
            title="Missing clickjacking protection (no X-Frame-Options / frame-ancestors)",
            severity=Severity.MEDIUM, category="A05:2021-Security Misconfiguration",
            endpoint=ex.url,
            description="The page can be framed by any origin, permitting clickjacking/UI-redress "
                        "attacks against authenticated actions.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            remediation="Set Content-Security-Policy: frame-ancestors 'none' (or 'self'), or "
                        "X-Frame-Options: DENY.",
            evidence=ex.as_evidence(),
        ))
    return out


def check_cookies(ex: Exchange) -> list[Finding]:
    out: list[Finding] = []
    for k, v in ex.response_headers.items():
        if k.lower() != "set-cookie":
            continue
        name = v.split("=", 1)[0].strip()
        low = v.lower()
        issues = []
        if "httponly" not in low:
            issues.append("HttpOnly")
        if "secure" not in low and ex.url.startswith("https"):
            issues.append("Secure")
        if "samesite" not in low:
            issues.append("SameSite")
        if issues:
            out.append(_finding(
                title=f"Cookie '{name}' missing attribute(s): {', '.join(issues)}",
                severity=Severity.LOW if "HttpOnly" not in issues else Severity.MEDIUM,
                category="A05:2021-Security Misconfiguration",
                endpoint=ex.url,
                description=f"The Set-Cookie for '{name}' is missing {', '.join(issues)}. "
                            "Session cookies without HttpOnly are readable by JavaScript "
                            "(XSS theft); without Secure they may leak over HTTP; without "
                            "SameSite they are more exposed to CSRF.",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                remediation="Set HttpOnly, Secure, and SameSite=Lax/Strict on session cookies.",
                evidence={"set_cookie": "<redacted>", **ex.as_evidence()},
            ))
    return out


def check_cors(ex: Exchange) -> list[Finding]:
    h = _h(ex)
    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials", "").lower()
    out: list[Finding] = []
    if acao == "*" and acac == "true":
        out.append(_finding(
            title="Insecure CORS: wildcard origin with credentials",
            severity=Severity.HIGH, category="A05:2021-Security Misconfiguration",
            endpoint=ex.url,
            description="The server returns Access-Control-Allow-Origin: * together with "
                        "Access-Control-Allow-Credentials: true. Browsers forbid this exact "
                        "combination, but it signals a misconfiguration that often reflects "
                        "the Origin instead, allowing any site to read authenticated responses.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
            impact="Cross-origin theft of authenticated data.",
            remediation="Never combine wildcard ACAO with credentials; reflect only an "
                        "explicit allowlist of trusted origins.",
            evidence=ex.as_evidence(),
        ))
    return out


_VERSION_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"}


def check_info_disclosure(ex: Exchange) -> list[Finding]:
    h = _h(ex)
    out: list[Finding] = []
    disclosed = {k: h[k] for k in _VERSION_HEADERS if k in h and re.search(r"\d", h[k])}
    if disclosed:
        out.append(_finding(
            title="Server/technology version disclosure in response headers",
            severity=Severity.INFO, category="A05:2021-Security Misconfiguration",
            endpoint=ex.url, confidence="high",
            description="Response headers reveal specific software versions, helping an "
                        f"attacker match known CVEs: {disclosed}",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            remediation="Suppress or genericize version banners (Server, X-Powered-By, etc.).",
            evidence=ex.as_evidence(),
        ))
    return out


_ERROR_PATTERNS = [
    (r"java\.lang\.[A-Za-z.]+Exception", "Java stack trace"),
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"<b>Warning</b>:.*on line <b>\d+", "PHP warning"),
    (r"SQLSTATE\[|SQL syntax.*MySQL|ORA-\d{5}|PostgreSQL.*ERROR", "SQL error"),
    (r"System\.[A-Za-z.]+Exception", ".NET exception"),
]


def check_error_disclosure(ex: Exchange) -> list[Finding]:
    body = ex.text
    out: list[Finding] = []
    for pat, label in _ERROR_PATTERNS:
        if re.search(pat, body):
            out.append(_finding(
                title=f"Verbose error / stack trace disclosure ({label})",
                severity=Severity.MEDIUM, category="A05:2021-Security Misconfiguration",
                endpoint=ex.url,
                description=f"The response contains a {label}, leaking internal paths, "
                            "framework details, or query structure useful for further attacks.",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                remediation="Return generic error pages; log details server-side only; "
                            "disable debug mode in production.",
                evidence=ex.as_evidence(),
            ))
            break
    return out


# Sensitive paths worth a single safe GET during recon.
SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/.env.local", "/config.json", "/wp-config.php.bak",
    "/.svn/entries", "/.DS_Store", "/backup.zip", "/.well-known/security.txt",
    "/server-status", "/actuator/health", "/actuator/env", "/phpinfo.php",
    "/debug", "/api/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
]


def check_sensitive_path(ex: Exchange, path: str) -> list[Finding]:
    """Interpret a fetched sensitive path. Only flags on a 200 with plausible content."""
    if ex.status != 200 or len(ex.body) == 0:
        return []
    body = ex.text
    signals = {
        "/.git/config": "[core]" in body,
        "/.env": re.search(r"^[A-Z0-9_]+=", body, re.M) is not None,
        "/.env.local": re.search(r"^[A-Z0-9_]+=", body, re.M) is not None,
        "/actuator/env": '"propertySources"' in body or '"activeProfiles"' in body,
        "/server-status": "Apache Server Status" in body,
        "/phpinfo.php": "phpinfo()" in body or "PHP Version" in body,
    }
    looks_real = signals.get(path, path in ("/api/swagger.json", "/openapi.json",
                                            "/swagger/v1/swagger.json") and
                             ('"openapi"' in body or '"swagger"' in body))
    if path in (".well-known/security.txt", "/.well-known/security.txt"):
        return []  # presence is good, not a finding
    if not looks_real:
        return []
    sev = Severity.HIGH if path in ("/.git/config", "/.env", "/.env.local", "/actuator/env") else Severity.MEDIUM
    return [_finding(
        title=f"Sensitive file exposed: {path}",
        severity=sev, category="A05:2021-Security Misconfiguration",
        endpoint=ex.url,
        description=f"{path} is publicly accessible and returns content consistent with a "
                    "sensitive file (source control metadata, environment secrets, or "
                    "internal configuration).",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    if sev == Severity.HIGH else
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        impact="May disclose credentials, source code, or internal configuration.",
        remediation="Block access to dotfiles/metadata/backups at the web server and remove "
                    "them from the web root.",
        evidence=ex.as_evidence(),
        confidence="high",
    )]


def run_passive(ex: Exchange) -> list[Finding]:
    """Run all header/body passive checks over one exchange."""
    out: list[Finding] = []
    for fn in (check_security_headers, check_cookies, check_cors,
               check_info_disclosure, check_error_disclosure):
        out.extend(fn(ex))
    return out
