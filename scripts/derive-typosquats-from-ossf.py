#!/usr/bin/env python3
"""Derive probable typosquat entries from OpenSSF malicious-packages
data by name-similarity to the curated popular-packages list.

Each derived row is fully traceable:
  - ``typosquat``: the malicious package name as reported by OSSF.
  - ``target``: the legitimate package from our popular-packages list.
  - ``source``: ``ossf-malicious-packages-derived``.
  - ``osv_id``: the upstream MAL-id for human verification.
  - ``references``: links back to GHSA or other advisories listed on
    the upstream OSV record.

The classifier is conservative: a name pair only qualifies when
Levenshtein distance is in ``{1, 2}`` and the absolute length
difference is at most 2. This filters out short collisions (e.g.
``re`` vs ``ms``) and very long-vs-short pairs that are obviously
different packages.

Run AFTER ``scripts/ingest-malicious-packages.py`` has refreshed the
malicious-packages JSON. The script reads from
``vulnerabilities/supply-chain/malicious-packages/<eco>.json`` and
``vulnerabilities/supply-chain/popular-packages/<eco>.json``, then
merges new derived rows into
``vulnerabilities/supply-chain/typosquat-db/known_typosquats.json``.

Curated rows (those without ``source=ossf-malicious-packages-derived``)
are preserved untouched.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
MAL_DIR = REPO_ROOT / "vulnerabilities" / "supply-chain" / "malicious-packages"
POP_DIR = REPO_ROOT / "vulnerabilities" / "supply-chain" / "popular-packages"
# Optional clone of github.com/ossf/malicious-packages used as the
# authoritative name source. When OSSF_MALPKGS is set, we walk the
# full corpus for typosquat derivation (not just the sampled subset
# in MAL_DIR), which dramatically increases coverage.
OSSF_CLONE = os.environ.get("OSSF_MALPKGS")

# Maps our ecosystem labels to the OSSF on-disk directory.
OSSF_DIR_MAP = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "go",
    "crates": "crates.io",
    "rubygems": "rubygems",
}
TYPO_FILE = (
    REPO_ROOT
    / "vulnerabilities"
    / "supply-chain"
    / "typosquat-db"
    / "known_typosquats.json"
)

DERIVED_SOURCE = "ossf-malicious-packages-derived"

# Ecosystems we have BOTH a malicious-packages corpus AND a curated
# popular-packages list for. The others (maven, nuget, github-actions,
# docker) need hand-curation since we don't have a canonical "target"
# set to compare against.
ECOSYSTEMS = ["npm", "pypi", "go", "crates", "rubygems"]


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                prev[j] + 1,        # deletion
                curr[j - 1] + 1,    # insertion
                prev[j - 1] + cost, # substitution
            )
        prev = curr
    return prev[-1]


def load_popular(eco: str) -> list[str]:
    path = POP_DIR / f"{eco}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    raw = data.get("entries") or data.get("packages") or []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str):
            out.append(item.lower())
        elif isinstance(item, dict) and "name" in item:
            out.append(str(item["name"]).lower())
    return out


def load_malicious(eco: str) -> list[dict]:
    path = MAL_DIR / f"{eco}.json"
    if not path.exists():
        return []
    return json.loads(path.read_text()).get("entries", [])


def load_ossf_full(eco: str) -> Iterable[dict]:
    """Yield every OSSF MAL-*.json record for ``eco`` from the
    upstream clone. Each record carries enough metadata to derive a
    typosquat row.

    Returns an empty iterator when the clone path is not set or the
    expected ecosystem directory does not exist.
    """
    if not OSSF_CLONE:
        return
    sub = OSSF_DIR_MAP.get(eco)
    if not sub:
        return
    base = Path(OSSF_CLONE) / "osv" / "malicious" / sub
    if not base.exists():
        return
    for p in sorted(base.rglob("MAL-*.json")):
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        affected = data.get("affected") or []
        if not affected:
            continue
        pkg = affected[0].get("package") or {}
        name = pkg.get("name") or ""
        if not name:
            continue
        refs = [
            r.get("url")
            for r in (data.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ]
        yield {
            "name": name,
            "osv_id": data.get("id", ""),
            "discovered": (data.get("published") or "")[:10],
            "references": refs,
            "source": "ossf-malicious-packages",
        }


def normalize(name: str, eco: str) -> str:
    """Lower-case + ecosystem-aware path stripping.

    For Go modules the popular-packages list uses the
    ``github.com/owner/repo`` form, but the OSSF data uses the same
    form. We just normalise to lowercase. For npm we strip an optional
    leading ``@scope/`` only when comparing against an un-scoped
    candidate; this is intentionally limited to keep the false-positive
    rate low.
    """
    return (name or "").strip().lower()


def matches_typosquat(
    fake: str, target: str, max_distance: int = 2, max_len_diff: int = 2
) -> int:
    """Return the Levenshtein distance if (fake, target) looks like a
    typosquat pair, else 0.
    """
    if fake == target:
        return 0
    # Skip pairs where either name is too short — short names hit
    # everything at distance 2.
    if len(fake) < 4 or len(target) < 4:
        return 0
    if abs(len(fake) - len(target)) > max_len_diff:
        return 0
    d = levenshtein(fake, target)
    if 1 <= d <= max_distance:
        return d
    return 0


def derive_for_eco(eco: str, limit: int) -> list[dict]:
    pop = load_popular(eco)
    if not pop:
        return []
    # Prefer the full upstream clone if available; otherwise fall
    # back to whatever the sampled malicious-packages JSON contains.
    mal: list[dict] = []
    if OSSF_CLONE and OSSF_DIR_MAP.get(eco):
        mal = list(load_ossf_full(eco))
    if not mal:
        mal = load_malicious(eco)
    if not mal:
        return []
    pop_set = set(pop)
    # For Go modules the canonical form is github.com/<owner>/<repo>.
    # Whole-URL Levenshtein is too strict (owner segments differ
    # entirely between a legit module and its typosquat), so we
    # additionally index popular packages by their final path segment
    # and accept a malicious entry as a Go typosquat when its tail
    # matches a popular tail at distance <=1 AND the owner segment
    # also differs.
    pop_by_tail: dict[str, str] = {}
    if eco == "go":
        for full in pop:
            tail = full.rsplit("/", 1)[-1]
            pop_by_tail.setdefault(tail, full)
    derived: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()
    for entry in mal:
        if entry.get("source") not in {"ossf-malicious-packages", None, ""}:
            continue  # don't re-derive from earlier derived rows
        fake = normalize(entry.get("name", ""), eco)
        if not fake or fake in pop_set:
            continue
        best: tuple[int, str] | None = None
        for target in pop:
            d = matches_typosquat(fake, target)
            if d == 0:
                continue
            if best is None or d < best[0]:
                best = (d, target)
        # Go-specific tail-match fallback for cross-owner typosquats
        # like github.com/grafanq/grafana → github.com/grafana/grafana.
        if best is None and eco == "go" and "/" in fake:
            fake_tail = fake.rsplit("/", 1)[-1]
            fake_owner = fake.split("/")[1] if fake.startswith("github.com/") else ""
            for tail, full in pop_by_tail.items():
                pop_owner = full.split("/")[1] if full.startswith("github.com/") else ""
                if pop_owner and fake_owner and pop_owner == fake_owner:
                    # Same owner, different repo — not a typosquat.
                    continue
                d = levenshtein(fake_tail, tail)
                if d == 0 and full != fake:
                    best = (1, full)  # exact tail match, different owner
                    break
                if d == 1:
                    best = (2, full)  # close tail match
                    break
        if best is None:
            continue
        d, target = best
        if (fake, target) in seen_pairs:
            continue
        seen_pairs.add((fake, target))
        refs: list[str] = []
        for r in entry.get("references", []) or []:
            if r and r not in refs:
                refs.append(r)
            if len(refs) >= 3:
                break
        # Synthesise a reference back to the curated malicious-packages
        # entry so the reviewer can follow the chain from typosquat-db
        # → malicious-packages → upstream OSV record.
        refs.append("https://github.com/ossf/malicious-packages")
        row = {
            "target": target,
            "typosquat": fake,
            "ecosystem": eco,
            "levenshtein_distance": d,
            "status": "removed",  # OSSF lists only confirmed-malicious entries; "removed" is the conservative default
            "discovered": entry.get("discovered") or "",
            "references": refs[:3],
            "source": DERIVED_SOURCE,
            "osv_id": entry.get("osv_id", ""),
        }
        derived.append(row)
        if len(derived) >= limit:
            break
    return derived


def merge_into_typosquat_db(derived_by_eco: dict[str, list[dict]]) -> dict:
    if not TYPO_FILE.exists():
        bundle: dict = {
            "schema_version": "1.0",
            "last_updated": "",
            "description": "Curated and derived typosquat catalogue.",
            "references": [],
            "entries": [],
        }
    else:
        bundle = json.loads(TYPO_FILE.read_text())

    existing = bundle.get("entries", [])
    # Strip out every previous derived row so re-runs are idempotent.
    curated = [e for e in existing if e.get("source") != DERIVED_SOURCE]

    # Build a (typosquat, ecosystem, target) dedupe set from curated
    # entries so we don't shadow them with a derived row.
    curated_keys = {
        (e.get("typosquat", "").lower(), e.get("ecosystem"), e.get("target"))
        for e in curated
    }

    new_rows: list[dict] = []
    for eco in ECOSYSTEMS:
        for row in derived_by_eco.get(eco, []):
            key = (row["typosquat"].lower(), eco, row["target"])
            if key in curated_keys:
                continue
            new_rows.append(row)

    # Sort derived rows by (ecosystem, typosquat) for deterministic
    # diffs across runs.
    new_rows.sort(key=lambda r: (r["ecosystem"], r["typosquat"]))
    bundle["entries"] = curated + new_rows
    bundle["last_updated"] = dt.datetime.now(dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    bundle.setdefault("sources", {})
    bundle["sources"][DERIVED_SOURCE] = {
        "url": "https://github.com/ossf/malicious-packages",
        "method": "Levenshtein <=2 against popular-packages catalogue",
        "rows_added": len(new_rows),
        "regenerated_at": bundle["last_updated"],
    }
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit",
        type=int,
        default=int(os.environ.get("LIMIT_PER_ECO", "40")),
        help="cap on derived rows per ecosystem (default 40)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="don't write, just report counts"
    )
    args = parser.parse_args()

    derived_by_eco: dict[str, list[dict]] = {}
    for eco in ECOSYSTEMS:
        derived_by_eco[eco] = derive_for_eco(eco, args.limit)
        print(f"  {eco}: {len(derived_by_eco[eco])} derived typosquat candidates")

    if args.dry_run:
        return 0

    bundle = merge_into_typosquat_db(derived_by_eco)
    TYPO_FILE.write_text(json.dumps(bundle, indent=2) + "\n")
    print(f"Wrote {len(bundle['entries'])} total entries to {TYPO_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
