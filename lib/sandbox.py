"""
lib/sandbox.py — Sandboxed build using bubblewrap (bwrap)

Builds AUR packages in a throwaway container:
  - No network access during build()
  - No access to home directory
  - Dies after build completes
  - No root required
"""

import subprocess
import tempfile
import os
from pathlib import Path


def build_in_sandbox(pkg: str, clone_dir: str = None):
    """
    Build a package inside a bubblewrap sandbox.
    Network is disabled after source fetch.
    """
    if clone_dir is None:
        clone_dir = _clone_package(pkg)

    print(f"  Building {pkg} in sandbox (no network, no home access)...")

    # First fetch sources outside sandbox (makepkg --nobuild just downloads)
    _fetch_sources(clone_dir)

    # Now build with network cut off
    _bwrap_build(clone_dir, pkg)


def _clone_package(pkg: str) -> str:
    tmpdir = tempfile.mkdtemp(prefix="gaur-build-")
    url = f"https://aur.archlinux.org/{pkg}.git"
    subprocess.run(
        ["git", "clone", "--depth=1", url, tmpdir],
        check=True, capture_output=True
    )
    return tmpdir


def _fetch_sources(clone_dir: str):
    """Download sources using makepkg --verifysource before sandboxing."""
    result = subprocess.run(
        ["makepkg", "--verifysource", "--skippgpcheck"],
        cwd=clone_dir,
    )
    if result.returncode != 0:
        raise RuntimeError("Source fetch/verification failed")


def _bwrap_build(clone_dir: str, pkg: str):
    """
    Run makepkg inside bubblewrap with:
      - New network namespace (no internet)
      - Read-only bind of /usr, /etc, /lib, /lib64
      - Tmpfs on /tmp and /home
      - Build dir as the only writable location
    """
    bwrap_cmd = [
        "bwrap",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/etc", "/etc",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib", "/lib64",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/bin", "/sbin",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--tmpfs", "/home",
        "--bind", clone_dir, clone_dir,
        "--chdir", clone_dir,
        "--unshare-net",          # <-- no network
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--",
        "makepkg", "--noconfirm", "--needed", "--noprogressbar",
    ]

    result = subprocess.run(bwrap_cmd, cwd=clone_dir)

    if result.returncode != 0:
        raise RuntimeError(f"Sandboxed build of {pkg} failed (exit {result.returncode})")

    # Find the built package
    pkgs = list(Path(clone_dir).glob("*.pkg.tar.*"))
    if not pkgs:
        raise RuntimeError("Build succeeded but no package file found")

    print(f"  ✓ Build complete: {pkgs[0].name}")

    # Install with pacman
    result = subprocess.run(
        ["sudo", "pacman", "-U", "--noconfirm", str(pkgs[0])]
    )
    if result.returncode != 0:
        raise RuntimeError("pacman -U failed")
