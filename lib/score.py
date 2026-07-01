"""
lib/score.py — Aggregate findings into a risk score

Combines findings from triage, PKGBUILD analysis, and URL checks
into a single risk level: OK / CAUTION / BLOCK
"""

from lib.triage import triage_findings


# Findings prefixed with ✗ that trigger a hard BLOCK. Deliberately does NOT
# include "orphaned"/"low votes"/"low popularity" — those are metadata signals
# about maintenance, not evidence of malicious content, so they only count
# toward CAUTION_THRESHOLD below like any other negative finding.
BLOCK_TRIGGERS = [
    "SKIP checksums",
    "curl|bash",
    "wget|bash",
    "eval of",
    "base64 decode-and-exec",
    "pipe to python",
    "URLhaus",
    "Domain",
]

# How many ✗ findings trigger CAUTION vs BLOCK
CAUTION_THRESHOLD = 2


def score_package(meta: dict, analysis: dict, url_findings: dict, whitelisted: bool = False) -> tuple[str, list]:
    """
    Returns (risk_level, all_findings) where risk_level is OK/CAUTION/BLOCK.

    whitelisted: package is in data/whitelist.txt (already manually reviewed).
    This only suppresses a CAUTION verdict down to OK — it never overrides a
    BLOCK, since BLOCK triggers (malicious content patterns, URLhaus hits,
    unverifiable checksums) are found fresh on every run and being previously
    reviewed doesn't mean this build is the one that was reviewed.
    """
    all_findings = []

    # Gather from all sources
    all_findings += triage_findings(meta)
    all_findings += analysis.get("findings", [])
    all_findings += url_findings.get("findings", [])

    # Hard block from analysis or URL check
    if analysis.get("blocked") or url_findings.get("blocked"):
        return "BLOCK", all_findings

    # Count negative findings
    negatives = [f for f in all_findings if f.startswith("✗")]

    # Check for specific block triggers in findings text
    for finding in negatives:
        for trigger in BLOCK_TRIGGERS:
            if trigger.lower() in finding.lower():
                return "BLOCK", all_findings

    if len(negatives) >= CAUTION_THRESHOLD:
        if whitelisted:
            all_findings.append("✓ pre-reviewed (whitelisted) — CAUTION suppressed")
            return "OK", all_findings
        return "CAUTION", all_findings

    return "OK", all_findings
