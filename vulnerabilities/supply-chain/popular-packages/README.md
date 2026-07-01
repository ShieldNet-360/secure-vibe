# Popular Packages

Per-ecosystem lists of high-profile package names used as the
reference set for runtime Levenshtein-distance typosquat detection in
the `check_typosquat` MCP tool.

Each `<ecosystem>.json` carries:

```json
{
  "schema_version": "1.0",
  "ecosystem": "npm",
  "description": "Top ~100 packages by install volume / popularity.",
  "packages": ["react", "lodash", ...]
}
```

The exact ordering inside `packages` does not matter; the tool
compares the input against every entry and surfaces any name within
edit distance 2. Lists are intentionally short (≈100 entries) so the
runtime cost stays in the microsecond range per call. Bigger lists
belong in `typosquat-db/` once a contributor has verified the
mapping.

These files are NOT a curated typosquat database — they are a
reference set of *legitimate* names. Treat additions as low-risk; the
worst-case impact of an inaccurate entry is a slightly less useful
suggestion in `potential_typosquats`.
