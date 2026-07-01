"""
lib/whitelist.py — pre-reviewed package whitelist

data/whitelist.txt: one package name per line, '#' comments and blank lines
ignored. Being whitelisted only suppresses a CAUTION verdict (see
lib/score.py) — it never overrides a BLOCK.
"""

from pathlib import Path

WHITELIST_PATH = Path(__file__).parent.parent / "data" / "whitelist.txt"


def load_whitelist() -> set:
    if not WHITELIST_PATH.exists():
        return set()
    names = set()
    for line in WHITELIST_PATH.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.add(line)
    return names


def is_whitelisted(name: str) -> bool:
    return name in load_whitelist()
