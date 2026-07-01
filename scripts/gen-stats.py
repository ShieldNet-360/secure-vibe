#!/usr/bin/env python3
"""Derive the homepage "by the numbers" stats from their source-of-truth files
and write docs/assets/data/stats.json, so the homepage stays in sync with the
repo automatically (no hand-editing index.md). Run as part of `make docs-data`.

Counts (each from a single authoritative source):
  - cve_patterns          : entries in vulnerabilities/cve/code-relevant/cve_patterns.json
  - secret_patterns       : `- id:` checks under `checks:` in the secret-detection checklist
  - assistant_integrations: names in compiler.AllTools() (the canonical distribution formatters)

The malicious-package / ecosystem / skills counts are derived client-side from
the existing malicious-packages.json / skills.json datasets; this file covers
the remaining curated numbers that have no other shipped dataset.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "docs" / "assets" / "data"
OUT = DATA / "stats.json"
HISTORY = DATA / "db-history.json"
MAL_DIR = REPO / "vulnerabilities" / "supply-chain" / "malicious-packages"


def cve_patterns() -> int:
    d = json.loads((REPO / "vulnerabilities" / "cve" / "code-relevant" / "cve_patterns.json").read_text())
    entries = d.get("entries", d if isinstance(d, list) else d.get("patterns", []))
    return len(entries)


def secret_patterns() -> int:
    text = (REPO / "skills" / "secret-detection" / "checklists" / "secret_detection.yaml").read_text()
    count = 0
    in_checks = False
    for line in text.splitlines():
        if re.match(r"^checks:", line):
            in_checks = True
            continue
        if in_checks and re.match(r"^[A-Za-z_]+:", line):  # next top-level key
            in_checks = False
        if in_checks and re.match(r"^- id:", line):
            count += 1
    return count


def assistant_integrations() -> int:
    text = (REPO / "cmd" / "secure-vibe" / "internal" / "compiler" / "compiler.go").read_text()
    m = re.search(r"func AllTools\(\).*?names\s*:?=\s*\[\]string\{([^}]*)\}", text, re.DOTALL)
    if not m:
        raise SystemExit("gen-stats: could not locate compiler.AllTools() names slice")
    return len(re.findall(r'"[^"]+"', m.group(1)))


def freshness() -> dict:
    """Most-recent curated-DB refresh date + the OSSF source it came from.

    `curated_last_updated` is the newest last_updated across the curated
    malicious-package files + the typosquat DB (ISO dates sort lexically).
    `ossf_*` is taken from the source block with the latest ingest.
    """
    mal_dir = REPO / "vulnerabilities" / "supply-chain" / "malicious-packages"
    typo = REPO / "vulnerabilities" / "supply-chain" / "typosquat-db" / "known_typosquats.json"
    updates: list[str] = []
    best_ingest = ""
    ossf_commit = ""
    ossf_ingested = ""
    for p in sorted(mal_dir.glob("*.json")):
        d = json.loads(p.read_text())
        if d.get("last_updated"):
            updates.append(d["last_updated"])
        src = d.get("sources", {}).get("ossf-malicious-packages", {})
        ingested = src.get("ingested_at", "")
        if ingested and ingested > best_ingest:
            best_ingest = ingested
            ossf_commit = (src.get("commit") or "")[:8]
            ossf_ingested = ingested
    if typo.exists():
        td = json.loads(typo.read_text())
        if isinstance(td, dict) and td.get("last_updated"):
            updates.append(td["last_updated"])
    return {
        "curated_last_updated": (max(updates)[:10] if updates else ""),
        "ossf_commit": ossf_commit,
        "ossf_ingested_at": ossf_ingested[:10] if ossf_ingested else "",
    }


def curated_total() -> int:
    return sum(len(json.loads(p.read_text()).get("entries", [])) for p in MAL_DIR.glob("*.json"))


def update_history(total: int) -> dict:
    """Append today's curated-DB size as a snapshot (one per UTC date), so the
    homepage can show growth over a window. Idempotent within a day."""
    hist = json.loads(HISTORY.read_text()) if HISTORY.exists() else {
        "description": "Curated malicious-package DB size over time.",
        "snapshots": [],
    }
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    snaps = {s["date"]: s for s in hist.get("snapshots", [])}
    snaps[today] = {"date": today, "total": total}
    hist["snapshots"] = [snaps[d] for d in sorted(snaps)]
    HISTORY.write_text(json.dumps(hist, indent=2) + "\n")
    return hist


def main() -> int:
    total = curated_total()
    update_history(total)
    stats = {
        "cve_patterns": cve_patterns(),
        "secret_patterns": secret_patterns(),
        "assistant_integrations": assistant_integrations(),
        "freshness": freshness(),
    }
    OUT.write_text(json.dumps(stats, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(REPO)} — {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
