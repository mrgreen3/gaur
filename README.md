# gaur

A safer, smarter AUR helper for ArchBang and Arch Linux.

`gaur` sits between you and the AUR, running a triage pipeline before a single line of a PKGBUILD executes. It filters noise, checks URLs, analyses PKGBUILD content statically, and builds in a sandbox — making the right thing the easy thing.

## Philosophy

The AUR's PKGBUILD is arbitrary bash that runs on your machine with your privileges. Most AUR helpers make it trivially easy to skip the one thing that matters: reading what you're about to run. `gaur` makes that impossible to skip, and does a lot of the checking for you automatically.

## Pipeline

Every install/update runs through these gates in order:

```
1. AUR Metadata Triage    — orphaned? flagged? stale? low votes?
2. PKGBUILD Static Analysis — SKIP checksums? curl|bash? eval? suspicious patterns?
3. URL Reputation Check   — known malicious domains? new domain? redirect chains?
4. Diff Review            — hard stop: show what changed since last reviewed commit
5. Sandboxed Build        — bubblewrap container, no network during build()
```

Packages are scored, not just blocked. You see exactly why gaur is concerned and make your own call.

## Usage

```bash
gaur install <package>     # install with full triage
gaur update                # update all AUR packages with diff review
gaur info <package>        # show triage report without installing
gaur search <term>         # search AUR
gaur --force-unsafe install <package>  # override (logged)
```

## Scoring

```
spotify 🟡 CAUTION
  ✗ -bin package (prebuilt binary)
  ✗ source URL is not spotify.com
  ✓ checksums present
  ✓ maintained (updated 3 weeks ago)
  ✓ 2847 votes
  → Proceed? [r]eview / [y]es / [N]o
```

```
dodgything-git 🔴 HIGH RISK
  ✗ orphaned (14 months)
  ✗ SKIP checksums
  ✗ curl|bash found in build()
  ✗ 4 votes
  ✗ eval() on downloaded content
  → Build blocked. Override with --force-unsafe
```

## Structure

```
gaur                  # main entry point
lib/
  triage.py           # AUR API metadata checks
  pkgbuild_analysis.py # static PKGBUILD analysis
  url_check.py        # URL reputation, domain age, redirect chains
  sandbox.py          # bubblewrap build isolation
  diff.py             # PKGBUILD diff review and commit pinning
  db.py               # local state (reviewed commits, install log)
  score.py            # aggregate findings into risk score
data/
  urlhaus.db          # local URLhaus feed (updated daily)
  whitelist.txt       # blessed packages (pre-reviewed)
```

## Dependencies

- `python` >= 3.10
- `bubblewrap` (bwrap) — for sandboxed builds
- `git` — for PKGBUILD diff tracking
- `whois` — for domain age checks
- `pacman` / `makepkg` — obviously

## Status

Early development. Not yet ready for production use.

## License

GPL-2.0
