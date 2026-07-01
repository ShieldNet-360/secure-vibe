#!/usr/bin/env python3
"""Generate the docs threat-intel dataset from the REAL curated malicious-package DB.

Merges every vulnerabilities/supply-chain/malicious-packages/<eco>.json into one
array (each entry tagged with its ecosystem) for the client-side browser on the
docs "Threat Intelligence" page. Output is committed (the docs CI just serves it),
and is fully reproducible: `make threat-data`.

No data is invented — this is a faithful projection of the curated, web-cited
canon. Run after editing the malicious-package DB.
"""
import json
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "vulnerabilities" / "supply-chain" / "malicious-packages"
OUT = REPO / "docs" / "assets" / "data" / "malicious-packages.json"

FIELDS = ("name", "versions_affected", "severity", "attack_type", "type",
          "discovered", "description", "references", "indicators")


def main() -> None:
    entries = []
    for f in sorted(SRC.glob("*.json")):
        eco = f.stem
        doc = json.loads(f.read_text())
        for e in doc.get("entries", []):
            row = {"ecosystem": eco}
            for k in FIELDS:
                if k in e and e[k] not in (None, "", [], {}):
                    row[k] = e[k]
            entries.append(row)
    entries.sort(key=lambda r: (r.get("discovered", ""), r["ecosystem"], r["name"]), reverse=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"count": len(entries), "entries": entries},
                              separators=(",", ":"), ensure_ascii=False))
    cited = sum(1 for e in entries if e.get("references"))
    print(f"wrote {OUT.relative_to(REPO)} — {len(entries)} entries, "
          f"{cited} with references ({100*cited//max(len(entries),1)}%), "
          f"{OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
