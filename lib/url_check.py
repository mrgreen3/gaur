"""
lib/url_check.py — URL reputation, domain age, redirect chain analysis

Checks source URLs against:
  - Local URLhaus feed (known malicious URLs/domains)
  - Domain age via WHOIS (new domains serving binaries = red flag)
  - Redirect chains (too many hops is suspicious)
  - TLS certificate validity
"""

import urllib.request
import urllib.parse
import subprocess
import sqlite3
import re
import os
from pathlib import Path

URLHAUS_DB = Path(__file__).parent.parent / "data" / "urlhaus.db"
MAX_REDIRECTS = 3
NEW_DOMAIN_DAYS = 180    # domains younger than this are flagged

# Shared hosting platforms where a domain hit in URLhaus is meaningless —
# any individual URL on these hosts could be malicious without tainting the domain.
SHARED_HOSTING_DOMAINS = frozenset({
    "github.com",
    "gitlab.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "sourceforge.net",
    "bitbucket.org",
    "codeberg.org",
    "launchpad.net",
    "drive.google.com",
    "dropbox.com",
    "onedrive.live.com",
})


def check_urls(sources: list) -> dict:
    """
    Check a list of source URLs.
    Returns dict with 'findings' list and 'blocked' bool.
    """
    findings = []
    blocked = False

    urls = [s for s in sources if s.startswith("http://") or s.startswith("https://")]

    if not urls:
        findings.append("✓ No remote source URLs (VCS or local)")
        return {"findings": findings, "blocked": False}

    for url in urls:
        # HTTP sources — no TLS at all
        if url.startswith("http://"):
            findings.append(f"⚠ Unencrypted source URL: {url}")

        domain = extract_domain(url)

        # URLhaus check
        if URLHAUS_DB.exists():
            hit = check_urlhaus(url, domain)
            if hit:
                findings.append(f"✗ URL/domain flagged in URLhaus feed: {domain}")
                blocked = True
                # Do not contact confirmed-malicious infrastructure.
                continue
            else:
                findings.append(f"✓ {domain} not in URLhaus feed")
        else:
            findings.append("⚠ URLhaus database not found — run 'gaur update-feeds'")

        # Redirect chain
        hops = count_redirects(url)
        if hops > MAX_REDIRECTS:
            findings.append(f"⚠ Source URL has {hops} redirects: {url}")
        elif hops > 0:
            findings.append(f"✓ {hops} redirect(s) for {domain}")

        # Domain age
        age_days = get_domain_age_days(domain)
        if age_days is not None:
            if age_days < NEW_DOMAIN_DAYS:
                findings.append(f"✗ Domain {domain} is only {age_days} days old")
                blocked = True
            else:
                findings.append(f"✓ Domain {domain} is {age_days} days old")

    return {"findings": findings, "blocked": blocked}


def extract_domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return url


def check_urlhaus(url: str, domain: str) -> bool:
    """Check URL and domain against local URLhaus SQLite database.

    For shared hosting platforms only the full URL is matched — domain-level
    hits are too broad (one malicious file taints the whole host).
    """
    try:
        conn = sqlite3.connect(URLHAUS_DB)
        cur = conn.cursor()
        if domain in SHARED_HOSTING_DOMAINS:
            cur.execute("SELECT 1 FROM urls WHERE url = ? LIMIT 1", (url,))
        else:
            cur.execute("SELECT 1 FROM urls WHERE url = ? OR domain = ? LIMIT 1",
                        (url, domain))
        result = cur.fetchone()
        conn.close()
        return result is not None
    except Exception:
        return False


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disallow urllib from automatically following 3xx responses.

    Returning None from redirect_request makes urllib raise HTTPError for
    3xx statuses, so the caller can inspect the Location header itself.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def count_redirects(url: str) -> int:
    """Follow redirects with HEAD requests, count hops.

    Uses a no-redirect opener so 3xx surfaces as HTTPError; the Location
    header is read manually and the hop count accumulated in a loop.
    Returns 0 on no redirect or any error.
    """
    try:
        opener = urllib.request.build_opener(_NoRedirectHandler)
        hops = 0
        current = url
        seen = set()
        while hops <= MAX_REDIRECTS + 2:
            if current in seen:
                break
            seen.add(current)
            req = urllib.request.Request(current, method="HEAD")
            req.add_header("User-Agent", "gaur/0.1")
            try:
                opener.open(req, timeout=8)
                break
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get("Location")
                    if location:
                        current = location
                        hops += 1
                        continue
                break
            except Exception:
                break
        return hops
    except Exception:
        return 0


_DOMAIN_AGE_CACHE: dict[str, int | None] = {}


_MONTH_ABBR = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def get_domain_age_days(domain: str) -> int | None:
    """
    Use whois to estimate domain age in days.
    Returns None if whois is unavailable or parsing fails.

    Results are cached per-domain so repeated source URLs sharing a host
    do not trigger redundant whois lookups.
    """
    if domain in _DOMAIN_AGE_CACHE:
        return _DOMAIN_AGE_CACHE[domain]

    result = None
    try:
        from datetime import datetime, timezone
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        )
        output = proc.stdout

        # Try common WHOIS date field patterns
        patterns = [
            r"(?:Creation Date|Created On|created|Domain Registration Date):\s*(\d{4}-\d{2}-\d{2})",
            r"(?:Creation Date|Created On|created):\s*(\d{4}-\d{2}-\d{2}T)",
            r"Registered on:\s*(\d{2}-\w{3}-\d{4})",
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if not match:
                continue
            date_str = match.group(1)
            try:
                if "-" in date_str and len(date_str.split("-")[0]) == 4:
                    # YYYY-MM-DD or YYYY-MM-DDT...
                    created = datetime.strptime(
                        date_str[:10], "%Y-%m-%d"
                    ).replace(tzinfo=timezone.utc)
                else:
                    # DD-Mon-YYYY (e.g. 01-Jan-2020) — parse manually to
                    # avoid locale-dependent %b behaviour.
                    day_s, mon_s, year_s = date_str.split("-")
                    mon = _MONTH_ABBR.get(mon_s)
                    if mon is None:
                        continue
                    created = datetime(
                        int(year_s), mon, int(day_s), tzinfo=timezone.utc
                    )
                now = datetime.now(timezone.utc)
                result = (now - created).days
                break
            except ValueError:
                continue
    except Exception:
        result = None

    _DOMAIN_AGE_CACHE[domain] = result
    return result
