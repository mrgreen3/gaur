"""
lib/triage.py — AUR API metadata checks

Fetches package metadata from the AUR RPC API and surfaces
orphaned, flagged, stale, and low-vote packages before anything runs.
"""

import urllib.request
import urllib.parse
import json
import time

AUR_RPC = "https://aur.archlinux.org/rpc/v5"

# Thresholds — tune these to taste
MIN_VOTES = 5
MAX_STALE_DAYS = 365          # flag if not updated in this many days
MAX_FLAGGED_DAYS = 90         # flag if out-of-date for this long


def triage_package(name: str) -> dict | None:
    """Fetch AUR metadata for a single package. Returns None if not found."""
    url = f"{AUR_RPC}/info?arg[]={urllib.parse.quote(name)}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read())
    except Exception as e:
        print(f"  ✗ AUR API error: {e}")
        return None

    if data.get("resultcount", 0) == 0:
        return None

    return data["results"][0]


def search_aur(term: str) -> list:
    """Search AUR by keyword. Returns list of result dicts."""
    url = f"{AUR_RPC}/search/{urllib.parse.quote(term)}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read())
        return data.get("results", [])
    except Exception as e:
        print(f"  ✗ AUR search error: {e}")
        return []


def triage_findings(meta: dict) -> list[str]:
    """
    Analyse AUR metadata and return a list of finding strings.
    Each string is prefixed with ✓ or ✗ for scoring.
    """
    findings = []
    now = int(time.time())

    # Orphaned
    if meta.get("Maintainer") is None:
        findings.append("✗ Package is orphaned (no maintainer)")

    # Flagged out of date
    ood = meta.get("OutOfDate")
    if ood:
        days_flagged = (now - ood) // 86400
        findings.append(f"✗ Flagged out of date ({days_flagged} days ago)")

    # Last modified
    last_mod = meta.get("LastModified", 0)
    days_stale = (now - last_mod) // 86400
    if days_stale > MAX_STALE_DAYS:
        findings.append(f"✗ Not updated in {days_stale} days")
    else:
        findings.append(f"✓ Last updated {days_stale} days ago")

    # Votes
    votes = meta.get("NumVotes", 0)
    if votes < MIN_VOTES:
        findings.append(f"✗ Very low votes ({votes})")
    else:
        findings.append(f"✓ {votes} votes")

    # Package type signals
    name = meta.get("Name", "")
    if name.endswith("-bin"):
        findings.append("✗ -bin package (prebuilt binary — cannot inspect build)")
    elif name.endswith("-git") or name.endswith("-svn") or name.endswith("-hg"):
        findings.append("⚠ VCS package (always builds HEAD — unauditable moving target)")

    # Popularity
    pop = meta.get("Popularity", 0)
    if pop < 0.001:
        findings.append(f"✗ Very low popularity score ({pop:.4f})")

    return findings
