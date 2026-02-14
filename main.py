from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

import re
import time
import socket
import ssl
from datetime import datetime

import requests
import dns.resolver
import whois

app = FastAPI(title="ReconAI (Recon Only)")
templates = Jinja2Templates(directory="templates")

# -----------------------
# Domain Validation
# -----------------------
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)

def normalize_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]
    return domain

def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


# -----------------------
# Recon Functions
# -----------------------
def get_whois(domain: str) -> dict:
    try:
        data = whois.whois(domain)
        return {
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
        }
    except Exception as e:
        return {"error": f"WHOIS failed: {e.__class__.__name__}"}


def get_dns(domain: str) -> dict:
    records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4

    def safe_resolve(rtype: str):
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                return [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
            if rtype == "TXT":
                out = []
                for r in answers:
                    joined = b"".join(r.strings).decode(errors="ignore") if hasattr(r, "strings") else str(r)
                    out.append(joined)
                return out
            return [str(r).rstrip('.') for r in answers]
        except Exception:
            return []

    for rtype in records.keys():
        records[rtype] = safe_resolve(rtype)

    return records


def get_http_headers(domain: str) -> dict:
    for scheme in ("https", "http"):
        try:
            response = requests.get(f"{scheme}://{domain}", timeout=6, allow_redirects=True)
            return {
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
            }
        except Exception:
            continue
    return {"error": "HTTP request failed"}


def get_ssl_info(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "serial_number": cert.get("serialNumber"),
                }
    except Exception as e:
        return {"error": f"SSL failed: {e.__class__.__name__}"}


def get_robots(domain: str) -> dict:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/robots.txt"
        try:
            r = requests.get(url, timeout=6, allow_redirects=True)
            if r.status_code == 200 and r.text:
                lines = [ln.strip() for ln in r.text.splitlines() if ln.strip()]
                disallow = [ln for ln in lines if ln.lower().startswith("disallow:")]
                sitemap = [ln for ln in lines if ln.lower().startswith("sitemap:")]
                return {
                    "url": r.url,
                    "found": True,
                    "disallow": disallow,
                    "sitemap": sitemap,
                    "raw_preview": lines[:60],
                }
            return {"url": r.url, "found": False}
        except Exception:
            continue
    return {"error": "robots.txt fetch failed"}


def enumerate_subdomains(domain: str, wordlist_path: str = "wordlist.txt") -> dict:
    found = []
    checked = 0
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.5

    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            words = [w.strip() for w in f.read().splitlines() if w.strip() and not w.startswith("#")]
    except Exception:
        words = []

    for w in words:
        checked += 1
        sub = f"{w}.{domain}"
        try:
            resolver.resolve(sub, "A")
            found.append(sub)
        except Exception:
            pass
        time.sleep(0.05)

    return {"checked": checked, "found": sorted(set(found))}


# -----------------------
# "AI" Risk Scoring (Heuristic)
# -----------------------
def _parse_cert_not_after(not_after: str):
    # Example format from ssl: "Aug 13 04:00:00 2026 GMT"
    if not not_after:
        return None
    try:
        return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        return None

def assess_risk(results: dict) -> dict:
    """
    Recon-only heuristic risk scoring.
    Output:
      score: 0-100
      level: Low/Medium/High
      reasons: list[str]
    """
    score = 0
    reasons = []

    http = results.get("http", {}) or {}
    sslr = results.get("ssl", {}) or {}
    robots = results.get("robots", {}) or {}
    subs = results.get("subdomains", {}) or {}

    # 1) HTTPS usage (based on final_url if we got one)
    final_url = (http.get("final_url") or "").lower()
    if final_url:
        if final_url.startswith("http://"):
            score += 20
            reasons.append("Site resolved to HTTP (not HTTPS) — traffic could be unencrypted.")
    else:
        score += 5
        reasons.append("HTTP(S) response not confirmed — unable to verify transport security.")

    # 2) Security headers (only if we have headers)
    headers = http.get("headers", {}) if isinstance(http.get("headers", {}), dict) else {}
    if headers:
        h_lower = {k.lower(): v for k, v in headers.items()}
        # missing common security headers -> modest risk bumps
        required = [
            ("strict-transport-security", 15, "Missing HSTS (Strict-Transport-Security)."),
            ("content-security-policy", 15, "Missing Content-Security-Policy (CSP)."),
            ("x-content-type-options", 8, "Missing X-Content-Type-Options."),
            ("x-frame-options", 8, "Missing X-Frame-Options."),
            ("referrer-policy", 6, "Missing Referrer-Policy."),
        ]
        for key, pts, msg in required:
            if key not in h_lower:
                score += pts
                reasons.append(msg)
    else:
        score += 5
        reasons.append("No HTTP headers captured — cannot assess security header posture.")

    # 3) TLS cert health
    if isinstance(sslr, dict) and "error" not in sslr:
        exp = _parse_cert_not_after(sslr.get("not_after"))
        if exp:
            days = (exp - datetime.utcnow()).days
            if days < 0:
                score += 30
                reasons.append("TLS certificate appears expired.")
            elif days <= 30:
                score += 15
                reasons.append("TLS certificate expires soon (≤30 days).")
        else:
            score += 5
            reasons.append("TLS certificate expiry could not be parsed.")
    else:
        # If site is HTTPS but we can't read TLS, still a signal.
        score += 10
        reasons.append("TLS info not available — cannot verify certificate details.")

    # 4) robots.txt sensitive hints
    if robots.get("found"):
        disallow = robots.get("disallow", []) or []
        keywords = ("admin", "login", "portal", "backup", "private", "staging", "dev")
        hit = []
        for line in disallow:
            low = line.lower()
            if any(k in low for k in keywords):
                hit.append(line)
        if hit:
            score += 10
            reasons.append("robots.txt disallows paths that look sensitive (admin/login/dev/staging).")

    # 5) Subdomains count (attack surface hint)
    found_subs = subs.get("found", []) or []
    if len(found_subs) >= 5:
        score += 10
        reasons.append("Multiple subdomains found — larger exposed attack surface.")
    elif 1 <= len(found_subs) <= 4:
        score += 5
        reasons.append("Some subdomains found — moderate attack surface expansion.")

    # Clamp score 0-100
    score = max(0, min(100, score))

    if score >= 70:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"

    return {"score": score, "level": level, "reasons": reasons}


# -----------------------
# Routes
# -----------------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("report.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, domain: str = Form(...)):
    domain = normalize_domain(domain)

    if not is_valid_domain(domain):
        return templates.TemplateResponse(
            "report.html",
            {"request": request, "error": "Invalid domain. Example: example.com", "domain": domain},
        )

    results = {
        "domain": domain,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "whois": get_whois(domain),
        "dns": get_dns(domain),
        "http": get_http_headers(domain),
        "ssl": get_ssl_info(domain),
        "robots": get_robots(domain),
        "subdomains": enumerate_subdomains(domain),
    }

    results["risk"] = assess_risk(results)

    return templates.TemplateResponse("report.html", {"request": request, "results": results, "domain": domain})


@app.post("/download")
async def download_report(domain: str = Form(...)):
    domain = normalize_domain(domain)

    if not is_valid_domain(domain):
        return Response(content="Invalid domain. Cannot generate report.", media_type="text/plain", status_code=400)

    results = {
        "domain": domain,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "whois": get_whois(domain),
        "dns": get_dns(domain),
        "http": get_http_headers(domain),
        "ssl": get_ssl_info(domain),
        "robots": get_robots(domain),
        "subdomains": enumerate_subdomains(domain),
    }

    results["risk"] = assess_risk(results)

    template = templates.get_template("report.html")
    html = template.render({"request": None, "results": results, "domain": domain})

    filename = f"recon_report_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.html"

    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
