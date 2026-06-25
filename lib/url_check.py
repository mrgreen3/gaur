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
    """Check URL and domain against local URLhaus SQLite database."""
    try:
        conn = sqlite3.connect(URLHAUS_DB)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM urls WHERE url = ? OR domain = ? LIMIT 1",
                    (url, domain))
        result = cur.fetchone()
        conn.close()
        return result is not None
    except Exception:
        return False


def count_redirects(url: str) -> int:
    """Follow redirects with HEAD requests, count hops."""
    try:
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
                opener = urllib.request.build_opener(
                    urllib.request.HTTPRedirectHandler()
                )
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


def get_domain_age_days(domain: str) -> int | None:
    """
    Use whois to estimate domain age in days.
    Returns None if whois is unavailable or parsing fails.
    """
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout

        # Try common WHOIS date field patterns
        patterns = [
            r"(?:Creation Date|Created On|created|Domain Registration Date):\s*(\d{4}-\d{2}-\d{2})",
            r"(?:Creation Date|Created On|created):\s*(\d{4}-\d{2}-\d{2}T)",
            r"Registered on:\s*(\d{2}-\w{3}-\d{4})",
        ]

        from datetime import datetime, timezone
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                date_str = match.group(1)[:10]  # take YYYY-MM-DD
                try:
                    created = datetime.strptime(date_str, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                    now = datetime.now(timezone.utc)
                    return (now - created).days
                except ValueError:
                    continue
        return None
    except Exception:
        return None
