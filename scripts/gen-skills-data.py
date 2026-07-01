#!/usr/bin/env python3
"""Generate the docs Skills-Catalogue dataset from the REAL skill frontmatter.

Reads every skills/<id>/SKILL.md YAML frontmatter into one array for the
client-side catalogue on the docs "Skills" page. Reproducible: `make skills-data`.
Faithful projection of the shipped skills — nothing invented.
"""
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "skills"
OUT = REPO / "docs" / "assets" / "data" / "skills.json"

try:
    import yaml
except ImportError:  # fall back to the venv interpreter's yaml if run bare
    raise SystemExit("PyYAML required: pip install pyyaml")

CWE = re.compile(r"(CWE-\d+)")


def main() -> None:
    rows = []
    for d in sorted(SRC.iterdir()):
        f = d / "SKILL.md"
        if not f.is_file():
            continue
        text = f.read_text()
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        if not m:
            continue
        fm = yaml.safe_load(m.group(1)) or {}
        sources = fm.get("sources", []) or []
        cwes = sorted({c for s in sources for c in CWE.findall(str(s))})
        rows.append({
            "id": fm.get("id", d.name),
            "title": fm.get("title", d.name),
            "description": fm.get("description", ""),
            "category": fm.get("category", ""),
            "severity": fm.get("severity", ""),
            "languages": fm.get("languages", []),
            "token_budget": fm.get("token_budget", {}),
            "applies_to": fm.get("applies_to", []),
            "related_skills": fm.get("related_skills", []),
            "sources": sources,
            "cwes": cwes,
            "external_tools": [t.get("name") for t in (fm.get("external_tools", []) or []) if isinstance(t, dict) and t.get("name")],
        })
    rows.sort(key=lambda r: r["title"].lower())
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"count": len(rows), "skills": rows},
                              separators=(",", ":"), ensure_ascii=False))
    print(f"wrote {OUT.relative_to(REPO)} — {len(rows)} skills, {OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
