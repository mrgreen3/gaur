"""
lib/pkgbuild_analysis.py — Static PKGBUILD analysis

Analyses PKGBUILD content as text BEFORE sourcing/executing it. This module
performs static text analysis only — it does not source the PKGBUILD. Note that
the later makepkg --verifysource step (in lib/sandbox.py) DOES source the
PKGBUILD on the host, so the review performed here matters.
"""

import re
import subprocess
import tempfile
import os
from pathlib import Path

AUR_GIT = "https://aur.archlinux.org"

# Patterns that are immediate red flags
BLOCK_PATTERNS = [
    (r"curl\s+.*\|\s*(ba)?sh",          "curl|bash pipe detected in PKGBUILD"),
    (r"wget\s+.*\|\s*(ba)?sh",          "wget|bash pipe detected in PKGBUILD"),
    (r"eval\s*\$\(",                     "eval of command substitution detected"),
    (r"eval\s*\$\{",                     "eval of variable expansion detected"),
    (r'eval\s+"?\$\(',                   "eval of subshell detected"),
    (r"base64\s+-d.*\|\s*(ba)?sh",      "base64 decode-and-exec detected"),
    (r"\|\s*python\s+-c",               "pipe to python -c detected"),
]

# Patterns worth flagging but not blocking
WARN_PATTERNS = [
    (r"\bsudo\b",                        "sudo used inside PKGBUILD"),
    (r"chmod\s+[0-7]{2,3}7(?![0-7])",   "world-writable chmod detected"),
    (r"curl\b",                          "network call (curl) in PKGBUILD body"),
    (r"wget\b",                          "network call (wget) in PKGBUILD body"),
    (r"\$\(curl",                        "command substitution with curl"),
    (r"rm\s+-rf\s+/",                   "rm -rf / pattern detected"),
    (r">\s*/etc/",                       "writing to /etc/ detected"),
    (r">\s*/usr/",                       "writing to /usr/ detected"),
    (r"if\s+\[.*\$USER",                "user-conditional logic detected"),
    (r"if\s+\[.*\$HOSTNAME",            "hostname-conditional logic detected"),
    (r"if\s+\[.*date\b",                "date-conditional logic detected (possible time bomb)"),
    (r"\bdate\b.*\bif\b",               "date check with conditional (possible time bomb)"),
]

SKIP_PATTERN = re.compile(r"(sha\d+sums|md5sums|b2sums)\s*=\s*\([^)]*'SKIP'", re.DOTALL)
INSTALL_FILE_PATTERN = re.compile(r"^install\s*=", re.MULTILINE)

_CHECKSUM_ARRAY_PATTERN = re.compile(
    r'(sha\d+sums|md5sums|b2sums)(?:_[a-zA-Z0-9_]+)?\s*=\s*\(([^)]*)\)',
    re.DOTALL | re.IGNORECASE,
)
_QUOTED_ENTRY_PATTERN = re.compile(r"""['"]([^'"]+)['"]""")
_VCS_SUFFIXES = ("-git", "-svn", "-hg", "-bzr")


def _checksum_skip_status(content: str) -> str:
    """
    Inspect checksum arrays and return:
      'none'    — no SKIP entries present
      'all'     — every checksum entry across all arrays is SKIP
      'partial' — mix of SKIP and real checksums
    """
    total = 0
    skip = 0
    for m in _CHECKSUM_ARRAY_PATTERN.finditer(content):
        for entry in _QUOTED_ENTRY_PATTERN.findall(m.group(2)):
            total += 1
            if entry.strip().upper() == "SKIP":
                skip += 1
    if skip == 0:
        return "none"
    if total > 0 and skip == total:
        return "all"
    return "partial"


def fetch_pkgbuild(name: str) -> str | None:
    """Clone the AUR git repo into a temp dir and return PKGBUILD contents."""
    tmpdir = tempfile.mkdtemp(prefix="gaur-")
    url = f"{AUR_GIT}/{name}.git"
    try:
        subprocess.run(
            ["git", "clone", "--depth=50", url, tmpdir],
            check=True, capture_output=True
        )
        pkgbuild_path = Path(tmpdir) / "PKGBUILD"
        if pkgbuild_path.exists():
            return pkgbuild_path.read_text(errors="replace"), tmpdir
        return None, tmpdir
    except subprocess.CalledProcessError:
        return None, tmpdir


def extract_sources(content: str) -> list:
    """Parse source URLs from PKGBUILD content. Returns list of source URLs."""
    sources = []
    pattern = re.compile(r'\bsource(?:_[a-zA-Z0-9_]+)?\s*=\s*\((.*?)\)', re.DOTALL | re.IGNORECASE)
    for match in pattern.finditer(content):
        source_block = match.group(1)
        # Extract quoted strings (handles 'url' and "url" syntax)
        for src in re.findall(r'["\']([^"\']+)["\']', source_block):
            # PKGBUILD syntax: "name::url" or just "url"
            if "::" in src:
                url = src.split("::", 1)[1]
            else:
                url = src
            # Only keep HTTP/HTTPS URLs (skip local files, variables)
            if url.startswith("http://") or url.startswith("https://"):
                sources.append(url)
    return sources


def analyse_pkgbuild(name: str, meta: dict) -> dict:
    """
    Fetch and statically analyse the PKGBUILD.
    Returns dict with 'findings', 'blocked', 'sources', 'clone_dir'.
    """
    findings = []
    blocked = False

    content, clone_dir = fetch_pkgbuild(name)
    if content is None:
        findings.append("✗ Could not fetch PKGBUILD")
        return {"findings": findings, "blocked": True, "sources": [], "clone_dir": clone_dir}

    # Extract sources for URL checking
    sources = extract_sources(content)

    # SKIP checksums — block or warn based on VCS convention
    if SKIP_PATTERN.search(content):
        status = _checksum_skip_status(content)
        if status == "all" and name.endswith(_VCS_SUFFIXES):
            findings.append("⚠ SKIP checksums (VCS package — expected by convention)")
        else:
            findings.append("✗ SKIP checksums — source integrity unverifiable")
            blocked = True
    else:
        findings.append("✓ Checksums present")

    # .install file — runs as root post-install
    if INSTALL_FILE_PATTERN.search(content):
        findings.append("⚠ .install file present (runs scripts as root on install/upgrade/remove)")

    # Block patterns
    for pattern, message in BLOCK_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(f"✗ {message}")
            blocked = True

    # Warn patterns (only flag if not already in a block pattern match)
    for pattern, message in WARN_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            # Don't double-report things already caught by block patterns
            if not any(message in f for f in findings):
                findings.append(f"⚠ {message}")

    return {
        "findings": findings,
        "blocked": blocked,
        "sources": sources,
        "clone_dir": clone_dir,
        "content": content,
    }
