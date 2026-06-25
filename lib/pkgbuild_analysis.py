"""
lib/pkgbuild_analysis.py — Static PKGBUILD analysis

Analyses PKGBUILD content as text BEFORE sourcing/executing it.
Sourcing a PKGBUILD IS executing it — we never do that.
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
    (r"chmod\s+[0-7]*7[0-7]{2}",        "world-writable chmod detected"),
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


def fetch_pkgbuild(name: str) -> str | None:
    """Clone the AUR git repo into a temp dir and return PKGBUILD contents."""
    tmpdir = tempfile.mkdtemp(prefix="gaur-")
    url = f"{AUR_GIT}/{name}.git"
    try:
        subprocess.run(
            ["git", "clone", "--depth=1", url, tmpdir],
            check=True, capture_output=True
        )
        pkgbuild_path = Path(tmpdir) / "PKGBUILD"
        if pkgbuild_path.exists():
            return pkgbuild_path.read_text(errors="replace"), tmpdir
        return None, tmpdir
    except subprocess.CalledProcessError:
        return None, tmpdir


def analyse_pkgbuild(name: str, meta: dict) -> dict:
    """
    Fetch and statically analyse the PKGBUILD.
    Returns dict with 'findings', 'blocked', 'pkgbuild_path', 'clone_dir'.
    """
    findings = []
    blocked = False

    content, clone_dir = fetch_pkgbuild(name)
    if content is None:
        findings.append("✗ Could not fetch PKGBUILD")
        return {"findings": findings, "blocked": True, "clone_dir": clone_dir}

    # SKIP checksums — hard block
    if SKIP_PATTERN.search(content):
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
        "clone_dir": clone_dir,
        "content": content,
    }
