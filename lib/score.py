"""
lib/score.py — Aggregate findings into a risk score

Combines findings from triage, PKGBUILD analysis, and URL checks
into a single risk level: OK / CAUTION / BLOCK
"""

from lib.triage import triage_findings


# Findings prefixed with ✗ that trigger a hard BLOCK
BLOCK_TRIGGERS = [
    "SKIP checksums",
    "curl|bash",
    "wget|bash",
    "eval of",
    "base64 decode-and-exec",
    "pipe to python",
    "URLhaus",
    "Domain",  # new domain finding
]

# How many ✗ findings trigger CAUTION vs BLOCK
CAUTION_THRESHOLD = 2


def score_package(meta: dict, analysis: dict, url_findings: dict) -> tuple[str, list]:
    """
    Returns (risk_level, all_findings) where risk_level is OK/CAUTION/BLOCK.
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
        return "CAUTION", all_findings

    return "OK", all_findings
