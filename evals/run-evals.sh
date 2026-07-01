#!/usr/bin/env bash
# Top-level eval harness for secure-vibe.
#
# Runs every check that can be evaluated *without* a live LLM:
#
#   1. `secure-vibe dev test secret-detection` over the corpus (passes
#      go-side regex parity + denylist + hotword logic).
#   2. The Python precision/recall benchmark (secure-vibe vs
#      gitleaks if installed). Output is written to
#      evals/baselines/secret-detection-static.md so the report is
#      diffable in PRs.
#   3. Static well-formedness checks on each fixture directory:
#      every fixture has an `expected.json` (or pointer README),
#      every `expected.json` parses, every cited `source` path
#      resolves to a real file in the repo.
#
# Items that require an LLM (the three `*.json` baselines under
# `baselines/`) are NOT executed by this script — see the README.
#
# Exit code: 0 on success, non-zero on the first failure.

set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

echo "==> 1. secure-vibe dev test secret-detection"
if ! command -v secure-vibe >/dev/null 2>&1; then
  if [[ -x ./secure-vibe ]]; then
    ALIAS=./secure-vibe
  elif [[ -x /tmp/secure-vibe ]]; then
    ALIAS=/tmp/secure-vibe
  else
    echo "    building secure-vibe ..."
    (cd cmd/secure-vibe && go build -o ../../secure-vibe)
    ALIAS=./secure-vibe
  fi
else
  ALIAS=secure-vibe
fi
"$ALIAS" test secret-detection

echo
echo "==> 2. precision/recall benchmark"
# Use a bash array, not an unquoted string, so a gitleaks binary path that
# contains spaces is passed through as a single argv element. Unquoted
# expansion would word-split such a path into multiple argparse arguments.
if [[ "${SKIP_GITLEAKS:-}" == "1" ]]; then
  GITLEAKS_OPT=(--gitleaks skip)
elif command -v gitleaks >/dev/null 2>&1; then
  GITLEAKS_OPT=(--gitleaks "$(command -v gitleaks)")
elif [[ -x "$HOME/go/bin/gitleaks" ]]; then
  GITLEAKS_OPT=(--gitleaks "$HOME/go/bin/gitleaks")
else
  GITLEAKS_OPT=(--gitleaks skip)
fi
python3 evals/benchmarks/secret-detection-vs-gitleaks.py \
  "${GITLEAKS_OPT[@]}" \
  --out evals/baselines/secret-detection-static.md
cat evals/baselines/secret-detection-static.md

echo
echo "==> 3. fixture well-formedness"
python3 - <<'PY'
import json, pathlib, sys
ROOT = pathlib.Path(".").resolve()
fail = 0
for exp in (ROOT / "evals/fixtures").rglob("expected.json"):
    try:
        d = json.loads(exp.read_text())
    except Exception as e:
        print(f"FAIL {exp}: invalid JSON: {e}")
        fail = 1
        continue
    for finding in d.get("expected_findings", []):
        src = finding.get("source")
        if src and not (ROOT / src).exists():
            print(f"FAIL {exp}: cited source path missing: {src}")
            fail = 1
for exp in (ROOT / "evals/fixtures").rglob("*.expected.json"):
    try:
        d = json.loads(exp.read_text())
    except Exception as e:
        print(f"FAIL {exp}: invalid JSON: {e}")
        fail = 1
        continue
    for finding in d.get("expected_findings", []):
        src = finding.get("source")
        if src and not (ROOT / src).exists():
            print(f"FAIL {exp}: cited source path missing: {src}")
            fail = 1
sys.exit(fail)
PY
echo "    fixture cross-references OK"

echo
echo "==> 4. scanner-eval (dependencies / cicd / dockerfile)"
# The scanner-eval harness drives secure-vibe mcp over JSON-RPC and scores
# every fixture under evals/fixtures/{dependency-choice,
# cicd-hardening, docker-hardening}/ against its expected.json. The
# harness builds secure-vibe mcp on demand if no binary is on PATH.
python3 evals/benchmarks/scanner-eval.py \
  --out evals/baselines/scanner-eval-static.md \
  --verbose
cat evals/baselines/scanner-eval-static.md

echo
echo "==> 5. generation-corpus oracle validation (keyless)"
# Static check of the generation fixtures: every code-generation fixture has a
# sibling expected.json with a valid ground_truth, compilable regex signals, a
# real declared skill, AND its own documented insecure/secure snippets score
# correctly under the deterministic classifier (guards against oracle drift).
python3 evals/benchmarks/llm-eval.py --validate-fixtures

echo
echo "==> 6. live-model eval pipeline (keyless self-check)"
# The LLM-tier baselines (no-instructions/minimal-skill/full-mcp) are
# bring-your-own-key and NOT run here. But the prevention-lift pipeline
# itself — fixture loading, tier execution, response classification, and
# lift computation — is exercised end to end through the deterministic
# MockProvider, which needs no API key and writes only to a tempdir.
# Asserts a positive SYNTHETIC lift so a regression in the harness fails
# CI even though no real model is called.
python3 evals/benchmarks/llm-eval.py --self-check

echo
echo "==> all eval checks passed"
