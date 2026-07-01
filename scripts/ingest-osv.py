#!/usr/bin/env python3
"""Populate the local OSV cache from osv.dev's bulk JSON exports.

The OSV project publishes per-ecosystem zip archives at
``https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip``.
Each archive contains one ``<OSV_ID>.json`` per advisory and is
refreshed nightly.

This script downloads the bulk archive for each ecosystem we support,
stride-samples a representative subset (configurable via
``--per-ecosystem``), and writes the per-record JSON into
``vulnerabilities/osv/<ecosystem>/<OSV_ID>.json``. Operators who want
full coverage should set ``--per-ecosystem`` to a large value (or 0,
meaning unlimited) and re-run weekly.

The cache layout is intentionally one-file-per-record so reviewers
can ``git diff`` individual advisories and so the MCP tool can lazily
load only the records it needs.

Refresh cadence
---------------
- Run weekly to pick up new entries.
- The ``secure-vibe update`` flow exposes this script as
  ``secure-vibe update --refresh-osv`` (added separately).
- Manual run: ``python3 scripts/ingest-osv.py --per-ecosystem 100``

Network requirements
--------------------
- Outbound HTTPS to ``osv-vulnerabilities.storage.googleapis.com``.
- ~25MB-200MB per ecosystem archive download (curl handles streaming).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = REPO_ROOT / "vulnerabilities" / "osv"

# osv.dev uses these ecosystem labels in its bulk-export URLs. The
# mapping is documented at https://google.github.io/osv.dev/data/.
#
# composer (Packagist), pub (Dart), and swift (SwiftURL) cover the
# major language ecosystems the scanner did not previously index. The
# osv.dev archive labels are taken verbatim from the documented bulk
# URL list; the local cache directories use the lowercase short name.
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "crates": "crates.io",
    "composer": "Packagist",
    "pub": "Pub",
    "swift": "SwiftURL",
}

# Default per-ecosystem sample size for the *repo-bundled* sample.
# The cap exists so the committed `vulnerabilities/osv/` tree stays
# small enough to clone and review (a full upstream pull is ~250 MB
# and ~16k JSON files). Operators who need full coverage at scan
# time should either:
#
#   - run `secure-vibe dev fetch-vulns` (default: pulls from osv.dev
#     into the user-local cache with --per-ecosystem 0), or
#   - run `secure-vibe dev fetch-vulns --from-release`, which pulls
#     the pre-built `osv-cache.tar.gz` published as a release asset.
#
# 100 (down from the previous 500/2000) keeps the bundled tree
# under ~10 MB while preserving the most operationally relevant
# advisories when combined with `--ordering latest-first` (the
# default the bundled sample is regenerated with).
DEFAULT_PER_ECO = 100

UA = "secure-vibe-osv-ingest/0.1"
BULK_URL = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"


def download_archive(ecosystem_label: str, dest: Path, verbose: bool) -> bool:
    url = BULK_URL.format(ecosystem_label)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
            shutil.copyfileobj(resp, fh)
    except Exception as exc:  # network failure, 404, etc.
        if verbose:
            print(f"    error: {exc}", file=sys.stderr)
        return False
    if verbose:
        print(f"    downloaded {dest.stat().st_size:,} bytes -> {dest}")
    return True


def stride_sample(items: list[str], target: int) -> list[str]:
    if target <= 0 or len(items) <= target:
        return items
    step = max(1, len(items) // target)
    sample = items[::step][:target]
    if len(sample) < target:
        sample.extend(items[len(sample) :][: target - len(sample)])
    return sample


# _SEVERITY_PRIORITY orders the four-bucket scale highest-first so a
# severity-priority sort puts CRITICAL/HIGH advisories at the head of
# the list and lets stride-sampling drop only the low-severity tail.
# Unknown / unscored records sort after "low" so they're the first
# casualties of a stride sample that doesn't reach them.
_SEVERITY_PRIORITY = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "": 4,
}


def _read_record(zf: zipfile.ZipFile, name: str) -> dict | None:
    """Read one OSV JSON record from the zip. Returns None on parse error."""
    try:
        with zf.open(name) as src:
            return json.loads(src.read())
    except Exception:
        return None


def extract_subset(
    zip_path: Path,
    dest_dir: Path,
    target: int,
    verbose: bool,
    severity_priority: bool = False,
    ordering: str = "stride",
) -> int:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        names = sorted(n for n in zf.namelist() if n.endswith(".json"))
        if not names:
            return 0
        if ordering == "latest-first" and (target == 0 or target < len(names)):
            # Re-order the candidate list so the newest advisories
            # (highest upstream `modified` timestamp) land at the head.
            # `head_sample` below then takes a contiguous prefix rather
            # than stride-sampling, so the offline-fallback subset is
            # always the most-recently-edited records — the most
            # operationally relevant ones for a scanner that may not
            # be able to reach osv.dev at runtime.
            modified_cache: dict[str, str] = {}
            for name in names:
                rec = _read_record(zf, name)
                if rec is None:
                    modified_cache[name] = ""
                    continue
                modified_cache[name] = rec.get("modified") or rec.get("published") or ""
            # Sort by modified desc; ties broken by name asc for
            # determinism across runs.
            names.sort(key=lambda n: (modified_cache.get(n, ""), n), reverse=False)
            names.sort(key=lambda n: modified_cache.get(n, ""), reverse=True)
        elif severity_priority and (target == 0 or target < len(names)):
            # Sort the candidate list so the most impactful advisories
            # land at the head before stride-sampling trims the tail.
            # We compute severity once per record (a JSON parse per file
            # is unavoidable to read database_specific.severity); the
            # secondary sort key keeps the result deterministic across
            # runs by falling back to the original name order.
            severity_cache: dict[str, str] = {}
            for name in names:
                rec = _read_record(zf, name)
                if rec is None:
                    severity_cache[name] = ""
                    continue
                severity_cache[name] = _severity_for_record(rec)
            names.sort(
                key=lambda n: (
                    _SEVERITY_PRIORITY.get(severity_cache.get(n, ""), 99),
                    n,
                )
            )
        if ordering == "latest-first":
            # Already sorted by modified desc — take the head N (not a
            # stride sample). This is the offline-fallback ordering
            # the repo bundles for secure-vibe mcp / secure-vibe.
            sample = names if target == 0 else names[:target]
        else:
            sample = stride_sample(names, target)
        written = 0
        for name in sample:
            try:
                with zf.open(name) as src:
                    body = src.read()
                json.loads(body)  # validate; raises on bad JSON
            except Exception as exc:
                if verbose:
                    print(f"    skip {name}: {exc}", file=sys.stderr)
                continue
            # CI's rule-file-schema check requires every vulnerability/**
            # JSON file to carry both `schema_version` and `last_updated`.
            # OSV records already have `schema_version`; surface `modified`
            # (the OSV equivalent of last_updated) as the latter.
            doc = json.loads(body)
            # Strip the verbose `details` field. The offline scanner never
            # reads it (it matches via index.json + the `severity`/`affected`
            # fields), and its prose routinely embeds the very payload it
            # documents — reverse shells, base64 blobs, `eval(...)` — which
            # trips endpoint AV (Microsoft Defender et al.) into quarantining
            # the bundled advisory JSON as "high-severity malware". Dropping
            # it removes the false-positive trigger and shrinks the tree
            # markedly. The short `summary` is kept for human-readable context.
            doc.pop("details", None)
            modified = doc.get("modified") or doc.get("published") or ""
            if modified and "last_updated" not in doc:
                doc["last_updated"] = modified[:10]
            body = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
            out = dest_dir / Path(name).name
            out.write_bytes(body)
            written += 1
        return written


# CVSS_V3_QUALITATIVE maps the GitHub-style severity band (in the
# OSV record's `database_specific.severity`) onto the four-bucket
# scale the Go-side scanner uses. GitHub publishes "MODERATE" for
# medium, but some adjacent feeds (incl. our own writers) emit
# "MEDIUM"; accept both.
_SEVERITY_BANDS = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

# CVSS v3 base-score qualitative ranges (NVD CVSS v3.1 spec).
_CVSS_V3_THRESHOLDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


def _bucket_for_score(score: float) -> str:
    for floor, label in _CVSS_V3_THRESHOLDS:
        if score >= floor:
            return label
    return ""


def _score_from_cvss_v3(vector: str) -> float:
    """Compute the CVSS v3.0/3.1 base score for the supplied vector.

    Mirrors the Go implementation in cmd/secure-vibe/internal/tools/
    osv_severity.go; kept in Python so the index emitted by
    ingest-osv.py already carries the bucketed severity and the
    Go-side fallback is the rare case.
    """
    metrics = {}
    for seg in vector.split("/"):
        seg = seg.strip()
        if not seg or ":" not in seg:
            continue
        k, v = seg.split(":", 1)
        k = k.strip().upper()
        if k == "CVSS":
            continue
        metrics[k] = v.strip().upper()
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", ""))
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", ""))
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", ""))
    scope = metrics.get("S")
    if av is None or ac is None or ui is None or scope not in ("U", "C"):
        return 0.0
    pr_table = (
        {"N": 0.85, "L": 0.62, "H": 0.27}
        if scope == "U"
        else {"N": 0.85, "L": 0.68, "H": 0.50}
    )
    pr = pr_table.get(metrics.get("PR", ""))
    impacts = {
        c: {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get(c, ""))
        for c in ("C", "I", "A")
    }
    if pr is None or any(v is None for v in impacts.values()):
        return 0.0
    iss = 1 - (1 - impacts["C"]) * (1 - impacts["I"]) * (1 - impacts["A"])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploit = 8.22 * av * ac * pr * ui
    if scope == "U":
        base = min(impact + exploit, 10.0)
    else:
        base = min(1.08 * (impact + exploit), 10.0)
    # CVSS v3 roundup: ceil to one decimal place.
    import math

    return math.ceil(base * 10) / 10


def _severity_for_record(data: dict) -> str:
    """Return the four-bucket severity for one OSV record, or "".

    Mirrors resolveOSVSeverity in osv_severity.go: prefer the
    GitHub-style database_specific.severity band, otherwise compute
    the maximum CVSS v3.x base score across the structured severity
    array. CVSS v2 / v4 vectors are left to the Go fallback (their
    formulas are kept in one place there).
    """
    band = ((data.get("database_specific") or {}).get("severity") or "").strip().upper()
    if band in _SEVERITY_BANDS:
        return _SEVERITY_BANDS[band]
    best = 0.0
    for entry in data.get("severity") or []:
        typ = (entry.get("type") or "").upper()
        score = (entry.get("score") or "").strip()
        if not score:
            continue
        # The score field may be a plain decimal (e.g. "7.5") or a
        # CVSS vector string. Try a numeric parse first.
        try:
            numeric = float(score)
        except ValueError:
            numeric = 0.0
            if typ.startswith("CVSS_V3"):
                numeric = _score_from_cvss_v3(score)
        if numeric > best:
            best = numeric
    return _bucket_for_score(best)


def write_index(dest_dir: Path) -> None:
    """Build an index.json listing every cached advisory.

    The MCP-side loader uses this so it can map a package name to its
    advisories in O(1) instead of scanning every file. We also embed
    a pre-computed `severity` field per index entry so the Go scanner
    can surface CVSS-derived severity without re-parsing each record
    on every lookup; the Go side still falls back to lazy on-disk
    parsing when an older index pre-dates this field.
    """
    now = dt.datetime.now(dt.timezone.utc)
    # last_updated is full RFC3339 so two regenerations on the same UTC
    # calendar day produce distinct values; CI's `last_updated must be
    # bumped` check is a string-equality test against the base branch,
    # and date-only granularity caused spurious failures whenever the
    # OSV index was rebuilt twice in the same day. The malicious-package
    # bundles already use the same format.
    index: dict = {
        "schema_version": "1.0",
        "last_updated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "by_package": {},
    }
    for path in sorted(dest_dir.glob("*.json")):
        if path.name == "index.json":
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        severity = _severity_for_record(data)
        affected = data.get("affected") or []
        for aff in affected:
            pkg = aff.get("package") or {}
            name = pkg.get("name")
            if not name:
                continue
            entry = {
                "id": data.get("id", path.stem),
                "file": path.name,
                "summary": data.get("summary", ""),
                "aliases": data.get("aliases", []),
            }
            if severity:
                entry["severity"] = severity
            index["by_package"].setdefault(name.lower(), []).append(entry)
    (dest_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ecosystem",
        action="append",
        choices=list(ECOSYSTEM_MAP),
        help="Limit to one ecosystem (repeatable). Default: all.",
    )
    parser.add_argument(
        "--per-ecosystem",
        type=int,
        default=int(os.environ.get("OSV_PER_ECO", str(DEFAULT_PER_ECO))),
        help=f"How many advisories to cache per ecosystem (default {DEFAULT_PER_ECO}, 0=unlimited).",
    )
    parser.add_argument(
        "--severity-priority",
        action="store_true",
        help=(
            "Sort each ecosystem's archive by severity (CRITICAL first) before"
            " stride-sampling so a smaller --per-ecosystem still captures the"
            " most impactful advisories. Costs one extra JSON parse per"
            " archive entry. Ignored when --ordering=latest-first."
        ),
    )
    parser.add_argument(
        "--ordering",
        choices=("stride", "latest-first"),
        default="stride",
        help=(
            "How to choose --per-ecosystem records out of the upstream"
            " archive. 'stride' (default) takes evenly-spaced records"
            " across the alphabetical OSV-ID order — a representative"
            " cross-section. 'latest-first' sorts by the upstream"
            " `modified` timestamp descending and takes the head, which"
            " biases the offline cache toward the most recently edited"
            " advisories. Use 'latest-first' for repo-bundled offline"
            " fallbacks; use 'stride' for representative test samples."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Where to write per-ecosystem JSONs. Defaults to the repo's"
            " vulnerabilities/osv/ directory; pass a user-cache path"
            " (e.g. ~/.cache/secure-vibe/vulns/osv/) when populating a"
            " runtime cache rather than the committed sample."
        ),
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    cache_root = args.output_dir if args.output_dir is not None else CACHE_DIR

    selected = args.ecosystem or list(ECOSYSTEM_MAP)
    tmp = REPO_ROOT / ".osv-tmp"
    tmp.mkdir(exist_ok=True)
    try:
        for eco in selected:
            label = ECOSYSTEM_MAP[eco]
            print(f"  {eco} ({label}):")
            zip_path = tmp / f"{eco}.zip"
            ok = download_archive(label, zip_path, args.verbose)
            if not ok:
                print("    download failed; skipping")
                continue
            dest = cache_root / eco
            # Wipe existing files so a smaller --per-ecosystem on a
            # subsequent run doesn't leave stale records behind.
            if dest.exists():
                for old in dest.glob("*.json"):
                    old.unlink()
            written = extract_subset(
                zip_path,
                dest,
                args.per_ecosystem,
                args.verbose,
                severity_priority=args.severity_priority,
                ordering=args.ordering,
            )
            print(f"    wrote {written} advisories -> {dest}")
            write_index(dest)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
