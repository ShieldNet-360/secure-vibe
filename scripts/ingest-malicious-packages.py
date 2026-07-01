#!/usr/bin/env python3
"""
Ingest entries from the OpenSSF malicious-packages corpus into
vulnerabilities/supply-chain/malicious-packages/<ecosystem>.json.

The OpenSSF corpus is the upstream source of truth for documented
malicious-package incidents (https://github.com/ossf/malicious-packages).
Each entry there is an OSV-format JSON record. This script reshapes
those records into the curated schema used by this repository while
preserving every hand-authored entry already present.

Authoritative source for each generated entry is captured per-row
via the `source`, `osv_id`, and `references` fields, so reviewers can
trace any row back to an upstream advisory.

Usage:
    # Clone the upstream corpus (or set $OSSF_MALPKGS to an existing clone).
    git clone --depth 1 https://github.com/ossf/malicious-packages.git \\
        /tmp/ossf-malpkgs
    OSSF_MALPKGS=/tmp/ossf-malpkgs python3 scripts/ingest-malicious-packages.py

The script is idempotent: re-running it with the same upstream commit
produces the same output. The targets per ecosystem are tuned to keep
the repo under ~500 KB additional weight while meeting the P4 plan
("500+ npm, 200+ PyPI, coverage across all 9 ecosystems").
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

# Map our repo's ecosystem filename to the OSSF subdirectory under osv/malicious/.
ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "go",
    "maven": "maven",
    "nuget": "nuget",
    "rubygems": "rubygems",
    "crates": "crates.io",
}

# Per-ecosystem target. The script samples evenly across the package
# namespace (by alphabetic stride) so the committed subset is stable
# across runs and reviewers can grep for any prefix of the upstream
# corpus.
DEFAULT_TARGETS: dict[str, int] = {
    "npm": 600,
    "pypi": 250,
    "go": 18,  # upstream only has 18 for Go
    "maven": 2,  # upstream only has 2 for Maven
    "nuget": 600,
    "rubygems": 300,
    "crates": 9,  # upstream only has 9 for crates.io
}

# github-actions and docker are intentionally not in ECOSYSTEM_MAP: the
# OSSF corpus has no entries for them today, and our existing curated
# entries for those ecosystems remain the source of truth.
HUMAN_ONLY_ECOSYSTEMS = ("github-actions", "docker")

REPO_ROOT = Path(__file__).resolve().parent.parent
MAL_DIR = REPO_ROOT / "vulnerabilities" / "supply-chain" / "malicious-packages"

# Per the OSSF "details" template, the description after the
# `_-= Per source details. Do not edit below this line.=-_` marker is
# boilerplate cleanup advice repeated on every row. We strip it so the
# committed description is just the incident-specific summary.
PER_SOURCE_RE = re.compile(
    r"\n*---\n_-= Per source details\. Do not edit below this line\.=-_\n.*",
    flags=re.DOTALL,
)


def find_clone() -> Path:
    """Locate the upstream OSSF malicious-packages clone."""
    candidates: list[Path] = []
    env = os.environ.get("OSSF_MALPKGS")
    if env:
        candidates.append(Path(env))
    candidates.append(Path("/tmp/ossf-malpkgs"))
    for c in candidates:
        if (c / "osv" / "malicious").is_dir():
            return c
    raise SystemExit(
        "OSSF clone not found. Run `git clone --depth 1 "
        "https://github.com/ossf/malicious-packages.git /tmp/ossf-malpkgs` "
        "first, or set $OSSF_MALPKGS to an existing clone."
    )


def upstream_commit(clone: Path) -> str:
    head = (clone / ".git" / "HEAD").read_text().strip()
    if head.startswith("ref:"):
        ref = head.split(" ", 1)[1].strip()
        return (clone / ".git" / ref).read_text().strip()
    return head


def gather_files(clone: Path, ossf_dir: str) -> list[Path]:
    """Walk the OSSF subdirectory and return every MAL-*.json file."""
    base = clone / "osv" / "malicious" / ossf_dir
    if not base.is_dir():
        return []
    return sorted(base.rglob("MAL-*.json"))


def stride_sample(paths: list[Path], target: int) -> list[Path]:
    """Pick `target` items spaced evenly across the sorted list."""
    if target >= len(paths):
        return paths
    if target <= 0:
        return []
    step = len(paths) / target
    out: list[Path] = []
    for i in range(target):
        out.append(paths[int(i * step)])
    return out


def parse_versions(affected: list[dict]) -> list[str]:
    """Best-effort extract of pinned versions from an OSV `affected` block."""
    versions: list[str] = []
    for a in affected:
        for v in a.get("versions", []) or []:
            if v not in versions:
                versions.append(v)
        for r in a.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                fix = ev.get("fixed")
                introduced = ev.get("introduced")
                # `introduced: 0` plus no fix means "all versions"; record
                # that as the empty list rather than literal "0".
                if fix and fix not in versions:
                    versions.append(f"<{fix}")
                elif introduced and introduced != "0" and introduced not in versions:
                    versions.append(f">={introduced}")
    return versions


def extract_attack_type(record: dict) -> str:
    """Pick a coarse attack-type tag from CWEs in the OSV record."""
    for a in record.get("affected", []):
        ds = a.get("database_specific", {})
        for cwe in ds.get("cwes", []) or []:
            cid = cwe.get("cweId", "")
            if cid == "CWE-506":
                return "embedded_malicious_code"
            if cid == "CWE-94":
                return "code_injection"
            if cid == "CWE-829":
                return "untrusted_inclusion"
    summary = (record.get("summary") or "").lower()
    if "typosquat" in summary:
        return "typosquatting"
    return "embedded_malicious_code"


def reshape(record: dict) -> dict | None:
    """Convert an OSSF OSV record into our curated schema row."""
    affected = record.get("affected", [])
    if not affected:
        return None
    pkg = affected[0].get("package", {})
    name = pkg.get("name")
    if not name:
        return None
    summary = (record.get("summary") or "").strip()
    details = PER_SOURCE_RE.sub("", record.get("details") or "").strip()
    description = summary or details or "Malicious package reported by OpenSSF."
    references = [
        r["url"] for r in record.get("references", []) if isinstance(r, dict) and r.get("url")
    ]
    discovered = (record.get("published") or "")[:10]
    versions = parse_versions(affected)
    osv_id = record.get("id") or ""
    # Validator (.github/workflows/validate.yml) requires every entry
    # to have at least one external reference URL. Many OSSF MAL-*
    # records have no upstream references, in which case we fall back
    # to the canonical osv.dev viewer URL — it's an authoritative
    # public source that resolves to the same advisory.
    if not references and osv_id:
        references = ["https://osv.dev/vulnerability/" + osv_id]
    aliases = record.get("aliases") or []

    row = {
        "name": name,
        "versions_affected": versions,
        "type": "malicious_code",
        "severity": "high",
        "discovered": discovered,
        "description": description if len(description) < 500 else description[:497] + "...",
        "references": references[:3],
        "indicators": [],
        "attack_type": extract_attack_type(record),
        "source": "ossf-malicious-packages",
        "osv_id": osv_id,
    }
    if aliases:
        row["aliases"] = aliases[:3]
    return row


def load_curated(eco: str) -> dict:
    path = MAL_DIR / f"{eco}.json"
    if not path.exists():
        return {
            "schema_version": "1.0",
            "ecosystem": eco,
            "last_updated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "entries": [],
        }
    return json.loads(path.read_text())


def merge(eco: str, generated: list[dict], commit: str) -> dict:
    """Merge generated rows into the curated file, preserving curated entries."""
    bundle = load_curated(eco)
    by_name: dict[str, dict] = {e["name"]: e for e in bundle.get("entries", [])}

    # Curated entries (anything without source="ossf-malicious-packages")
    # always win — they have richer context than the upstream summary.
    curated = [
        e for e in bundle.get("entries", []) if e.get("source") != "ossf-malicious-packages"
    ]
    curated_names = {e["name"] for e in curated}

    additions: list[dict] = []
    for row in generated:
        if row["name"] in curated_names:
            continue
        additions.append(row)

    additions.sort(key=lambda r: r["name"].lower())
    bundle["entries"] = curated + additions
    bundle["last_updated"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle.setdefault("sources", {})
    bundle["sources"]["ossf-malicious-packages"] = {
        "url": "https://github.com/ossf/malicious-packages",
        "commit": commit,
        "ingested_at": bundle["last_updated"],
        "entries_from_source": len(additions),
    }
    return bundle


def ingest(eco: str, target: int, clone: Path, commit: str, verbose: bool) -> tuple[int, int]:
    ossf_dir = ECOSYSTEM_MAP[eco]
    files = gather_files(clone, ossf_dir)
    chosen = stride_sample(files, target)
    rows: list[dict] = []
    for p in chosen:
        try:
            record = json.loads(p.read_text())
        except Exception as ex:  # noqa: BLE001
            if verbose:
                print(f"  skip {p}: {ex}", file=sys.stderr)
            continue
        row = reshape(record)
        if row is None:
            continue
        rows.append(row)
    bundle = merge(eco, rows, commit)
    out = MAL_DIR / f"{eco}.json"
    out.write_text(json.dumps(bundle, indent=2) + "\n")
    return len(bundle["entries"]), len(rows)


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ecosystem", action="append", help="Limit to specific ecosystem(s).")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="Print summary without writing files.")
    args = p.parse_args(list(argv) if argv is not None else None)

    clone = find_clone()
    commit = upstream_commit(clone)
    print(f"OSSF malicious-packages: {clone} @ {commit}")

    targets = {k: v for k, v in DEFAULT_TARGETS.items()}
    selected = args.ecosystem or list(targets.keys())

    for eco in selected:
        if eco not in ECOSYSTEM_MAP:
            print(f"  skip {eco}: no upstream mapping", file=sys.stderr)
            continue
        target = targets.get(eco, 100)
        if args.dry_run:
            files = gather_files(clone, ECOSYSTEM_MAP[eco])
            print(f"  {eco}: would sample {min(target, len(files))} of {len(files)} upstream entries")
            continue
        total, added = ingest(eco, target, clone, commit, args.verbose)
        print(f"  {eco}: ingested {added} new rows (total in file: {total})")

    for eco in HUMAN_ONLY_ECOSYSTEMS:
        path = MAL_DIR / f"{eco}.json"
        if path.exists():
            n = len(json.loads(path.read_text()).get("entries", []))
            print(f"  {eco}: {n} curated entries (no upstream ingest)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
