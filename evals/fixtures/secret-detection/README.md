# `evals/fixtures/secret-detection`

Source-of-truth corpus for the secret-detection skill lives at
[`skills/secret-detection/tests/corpus.json`](../../../skills/secret-detection/tests/corpus.json).

That file is the actual benchmark input — every fixture there has an
`expected: detect` or `expected: ignore` tag, plus a `reason`
(for ignore cases) or `expected_pattern` (for detect cases).
The benchmark at
[`../../benchmarks/secret-detection-vs-gitleaks.py`](../../benchmarks/secret-detection-vs-gitleaks.py)
reads that file directly — there is no duplicate copy here.

This directory exists so the `evals/fixtures/` tree has the same shape
as the other eval categories. It also holds any companion *whole-file*
samples that don't fit cleanly in the JSON corpus (e.g. a 200-line
log file containing a single planted secret). When you add a sample
file here, also add a one-row pointer to it in the JSON corpus so the
benchmark harness picks it up.
