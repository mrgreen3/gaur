"""
lib/diff.py — PKGBUILD diff review and commit pinning

On first install: show full PKGBUILD for review.
On updates: show only what changed since last reviewed commit.
Hard stop until user acknowledges.
"""

import subprocess
import os
from pathlib import Path
from lib.db import GaurDB


def review_diff(pkg: str, db: GaurDB, clone_dir: str = None):
    """
    Show PKGBUILD diff since last reviewed commit.
    Block until user acknowledges.
    """
    last_commit = db.get_reviewed_commit(pkg)

    if clone_dir is None:
        import tempfile
        clone_dir = tempfile.mkdtemp(prefix="gaur-")
        url = f"https://aur.archlinux.org/{pkg}.git"
        subprocess.run(["git", "clone", "--depth=5", url, clone_dir],
                       check=True, capture_output=True)

    pkgbuild = Path(clone_dir) / "PKGBUILD"
    current_commit = get_head_commit(clone_dir)

    print("\n" + "─" * 60)

    if last_commit is None:
        # First install — show full PKGBUILD
        print(f"  First install of {pkg}. Review full PKGBUILD:\n")
        print(pkgbuild.read_text(errors="replace"))
    elif last_commit == current_commit:
        print(f"  PKGBUILD unchanged since last review ({last_commit[:8]}). ✓")
        return
    else:
        # Show diff since last reviewed commit
        print(f"  PKGBUILD changed since last review ({last_commit[:8]} → {current_commit[:8]}):\n")
        try:
            result = subprocess.run(
                ["git", "diff", last_commit, current_commit, "--", "PKGBUILD"],
                cwd=clone_dir, capture_output=True, text=True
            )
            diff = result.stdout
            if diff.strip():
                _print_diff(diff)
            else:
                print("  (no diff output — may be outside shallow clone depth)")
        except Exception as e:
            print(f"  ✗ Could not generate diff: {e}")
            print("  Showing current PKGBUILD:\n")
            print(pkgbuild.read_text(errors="replace"))

    print("─" * 60)

    # Hard stop
    while True:
        reply = input("\n  Mark as reviewed and continue? [y]es / [N]o: ").strip().lower()
        if reply == "y":
            db.set_reviewed_commit(pkg, current_commit)
            print(f"  ✓ Commit {current_commit[:8]} marked as reviewed.\n")
            return
        elif reply in ("n", ""):
            print("  Aborted.\n")
            raise SystemExit(0)


def get_head_commit(clone_dir: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=clone_dir, capture_output=True, text=True
    )
    return result.stdout.strip()


def _print_diff(diff: str):
    """Print diff with simple colour if terminal supports it."""
    use_colour = os.isatty(1)
    RED = "\033[31m" if use_colour else ""
    GREEN = "\033[32m" if use_colour else ""
    CYAN = "\033[36m" if use_colour else ""
    RESET = "\033[0m" if use_colour else ""

    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            print(f"{CYAN}{line}{RESET}")
        elif line.startswith("+"):
            print(f"{GREEN}{line}{RESET}")
        elif line.startswith("-"):
            print(f"{RED}{line}{RESET}")
        elif line.startswith("@@"):
            print(f"{CYAN}{line}{RESET}")
        else:
            print(line)
