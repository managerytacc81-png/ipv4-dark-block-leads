"""Liveness and Dormant-Holder Scoring Module.

Checks:
1. RDAP / WHOIS lookup for legal entity (OrgName), NetName, and technical/admin POC emails.
2. Domain resolution (DNS A record check).
3. Mail exchanger liveness (DNS MX record check).
4. Multi-factor Dormant-Holder Likelihood scoring model.
"""

import html
import json
import logging
import re
import socket
import subprocess
import urllib.request
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ARIN_RDAP_IP_URL = "https://rdap.arin.net/registry/ip/"
RIPE_RDAP_IP_URL = "https://rdap.db.ripe.net/ip/"
RIPESTAT_WHOIS_URL = "https://stat.ripe.net/data/whois/data.json?resource="

# In-memory caches to speed up repeated queries
_DNS_CACHE: Dict[str, Tuple[bool, bool]] = {}
_ORG_CACHE: Dict[str, Dict] = {}


def extract_domain_from_email(email: str) -> Optional[str]:
    """Extract domain from an email address."""
    if not email or "@" not in email:
        return None
    domain = email.split("@")[-1].strip().lower()
    # Basic sanitize
    domain = re.sub(r"[^\w\.-]", "", domain)
    return domain if "." in domain else None


def clean_org_name(org_name: str) -> str:
    """Unescape HTML and strip unwanted trailing punctuation."""
    if not org_name:
        return ""
    cleaned = html.unescape(org_name).strip()
    return cleaned


def guess_domain_from_org(org_name: str) -> Optional[str]:
    """Infer candidate domain name from organization name."""
    if not org_name:
        return None
    name = org_name.lower()
    # Strip common suffixes
    for suffix in [
        " llc", " inc.", " inc", " corp.", " corp", " corporation",
        " ltd", " gmbh", " s.a.", " limited", " company", " co.", " co"
    ]:
        if name.endswith(suffix):
            name = name[:-len(suffix)].strip()
            
    # Remove non-alphanumeric chars except dash
    clean = re.sub(r"[^a-z0-9\-]", "", name)
    if clean and len(clean) >= 3:
        return f"{clean}.com"
    return None


def check_domain_liveness(domain: Optional[str], timeout: float = 3.0) -> Tuple[bool, bool]:
    """Perform DNS A record and MX record checks on domain.
    
    Returns (domain_resolves, mx_alive).
    """
    if not domain:
        return False, False
        
    domain_clean = domain.strip().lower()
    if domain_clean in _DNS_CACHE:
        return _DNS_CACHE[domain_clean]

    resolves = False
    mx_alive = False

    # 1. Check A / AAAA resolution via getaddrinfo
    try:
        addrinfo = socket.getaddrinfo(domain_clean, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolves = len(addrinfo) > 0
    except (socket.gaierror, socket.timeout, OSError):
        resolves = False

    # 2. Check MX records via dig
    try:
        proc = subprocess.run(
            ["dig", "+short", "MX", domain_clean],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            mx_lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            mx_alive = len(mx_lines) > 0
    except Exception:
        # Fallback: if MX check fails or dig is missing, if domain resolves, mail might be handled
        mx_alive = False

    _DNS_CACHE[domain_clean] = (resolves, mx_alive)
    return resolves, mx_alive


def lookup_org_and_contacts(
    ip_or_prefix: str,
    rir: str = "ARIN",
    opaque_id: str = "",
    timeout: int = 5,
) -> Dict:
    """Fetch organization name, contacts, and emails from RDAP / WHOIS."""
    cache_key = f"{rir}:{ip_or_prefix}"
    if cache_key in _ORG_CACHE:
        return _ORG_CACHE[cache_key]

    ip = ip_or_prefix.split("/")[0]
    org_name = ""
    net_name = ""
    emails: List[str] = []
    
    # Select RDAP endpoint based on RIR
    rdap_base = RIPE_RDAP_IP_URL if rir.upper() == "RIPE" else ARIN_RDAP_IP_URL
    url = f"{rdap_base}{ip}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Dormant-IPv4-Detector/1.0 (+https://github.com/revenue-eval)"}
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            net_name = data.get("name", "")
            
            def parse_vcard(vcard):
                nonlocal org_name
                if not vcard or len(vcard) < 2:
                    return
                for item in vcard[1]:
                    if item[0] == "fn" and not org_name:
                        org_name = item[3]
                    elif item[0] == "email":
                        emails.append(item[3])

            for e in data.get("entities", []):
                parse_vcard(e.get("vcardArray"))
                for sub in e.get("entities", []):
                    parse_vcard(sub.get("vcardArray"))
    except Exception as e:
        logger.debug("RDAP lookup failed for %s (%s): %s", ip, rir, e)

    # Fallback to RIPEstat WHOIS if RDAP didn't yield org
    if not org_name:
        try:
            ws_url = f"{RIPESTAT_WHOIS_URL}{ip_or_prefix}"
            ws_req = urllib.request.Request(
                ws_url,
                headers={"User-Agent": "Dormant-IPv4-Detector/1.0 (+https://github.com/revenue-eval)"}
            )
            with urllib.request.urlopen(ws_req, timeout=timeout) as ws_resp:
                ws_data = json.loads(ws_resp.read().decode("utf-8"))
                for rec in ws_data.get("data", {}).get("records", []):
                    for item in rec:
                        k = item.get("key", "").lower()
                        v = item.get("value", "").strip()
                        if k in ("org-name", "orgname") and not org_name:
                            org_name = v
                        elif k in ("netname", "net-name") and not net_name:
                            net_name = v
                        elif k in ("e-mail", "email"):
                            emails.append(v)
        except Exception as e:
            logger.debug("RIPEstat WHOIS fallback failed for %s: %s", ip_or_prefix, e)

    # Clean org name or fallback to net_name or opaque_id
    final_org = clean_org_name(org_name) or clean_org_name(net_name) or (f"ORG-{opaque_id[:8]}" if opaque_id else "Unknown Holder")
    
    result = {
        "org": final_org,
        "net_name": net_name,
        "emails": list(set(emails)),
    }
    _ORG_CACHE[cache_key] = result
    return result


def score_dormant_likelihood(
    unannounced: bool,
    is_legacy: bool,
    alloc_date: str,
    domain_resolves: bool,
    mx_alive: bool,
    ips: int,
) -> Tuple[float, str, Dict[str, float]]:
    """Compute dormant-holder likelihood score (0 - 100) and priority category.
    
    Scoring factors:
    - Block unannounced (100% dark in BGP): +35 pts
    - Legacy status (pre-19971222, unencumbered title): +25 pts
    - Domain resolves (corporate entity confirmed active): +15 pts
    - MX alive (mail server active, reachable executives): +10 pts
    - Block size >= /20 (>= 4096 IPs, substantial broker incentive): +10 pts
    - Vintage allocation (over 20 years old): +5 pts
    """
    breakdown = {}
    score = 0.0

    if unannounced:
        score += 35.0
        breakdown["unannounced_dark_bgp"] = 35.0
    else:
        breakdown["unannounced_dark_bgp"] = 0.0

    if is_legacy:
        score += 25.0
        breakdown["legacy_status"] = 25.0
    else:
        breakdown["legacy_status"] = 0.0

    if domain_resolves:
        score += 15.0
        breakdown["domain_resolves"] = 15.0
    else:
        breakdown["domain_resolves"] = 0.0

    if mx_alive:
        score += 10.0
        breakdown["mx_alive"] = 10.0
    else:
        breakdown["mx_alive"] = 0.0

    if ips >= 4096:
        score += 10.0
        breakdown["size_ge_20"] = 10.0
    elif ips >= 1024:
        score += 5.0
        breakdown["size_ge_22"] = 5.0
    else:
        breakdown["size_small"] = 0.0

    if alloc_date and alloc_date.isdigit() and len(alloc_date) >= 4:
        try:
            year = int(alloc_date[:4])
            if year > 0 and year <= 2006:
                score += 5.0
                breakdown["vintage_20yr"] = 5.0
        except ValueError:
            pass

    score = min(100.0, score)

    if score >= 80.0:
        priority = "PRIME_TARGET"
    elif score >= 60.0:
        priority = "HIGH"
    elif score >= 40.0:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return score, priority, breakdown
