#!/usr/bin/env python3
"""Generate the docs Compliance-matrix dataset from the REAL mapping files.

Reads compliance/*.yaml (SOC 2 / HIPAA / PCI-DSS control→skill mappings) into one
array for the client-side coverage matrix on the docs "Compliance" page.
Reproducible: `make compliance-data`. Faithful projection — nothing invented.
"""
import json
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "compliance"
OUT = REPO / "docs" / "assets" / "data" / "compliance.json"

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML required: pip install pyyaml")


def main() -> None:
    frameworks = []
    for f in sorted(SRC.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text()) or {}
        controls = doc.get("controls", []) or []
        frameworks.append({
            "framework": doc.get("framework", f.stem),
            "version": doc.get("version", ""),
            "control_count": len(controls),
            "controls": [{
                "id": c.get("id", ""),
                "title": c.get("title", ""),
                "description": c.get("description", ""),
                "skills": c.get("skills", []) or [],
                "references": c.get("references", []) or [],
            } for c in controls],
        })
    total = sum(fw["control_count"] for fw in frameworks)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"control_count": total, "frameworks": frameworks},
                              separators=(",", ":"), ensure_ascii=False))
    print(f"wrote {OUT.relative_to(REPO)} — {len(frameworks)} frameworks, "
          f"{total} controls, {OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
