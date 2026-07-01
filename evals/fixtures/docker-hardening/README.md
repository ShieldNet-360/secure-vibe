# Dockerfile hardening fixtures

Dockerfiles paired with `*.expected.json` files describing the
findings the scanner is expected to surface. The set deliberately
spans the multi-stage, ARG-substituted, and continuation-line edge
cases that the line-oriented regex pass mis-handles, plus single-
rule fixtures for the rules that don't already have dedicated
coverage.

| Fixture | Notes |
|---|---|
| `clean.Dockerfile` | Pinned tag, non-root user, no remote ADD — zero findings. |
| `all-bad.Dockerfile` | Hits every Dockerfile rule the scanner implements. |
| `multi-stage-root-in-builder.Dockerfile` | `USER root` only in builder stage; the final stage uses uid 10001. The AST pass should suppress `dkr-non-root-user`. |
| `multiline-run.Dockerfile` | `curl ... \\ \| sh` across a backslash continuation. The joined-line view should still surface `dkr-no-curl-pipe-sh`. |
| `arg-driven-from.Dockerfile` | `ARG BASE_IMAGE=node:latest` + `FROM $BASE_IMAGE`. The AST pass should resolve the ARG and flag `dkr-explicit-latest-tag`. |
| `latest-only-builder.Dockerfile` | `:latest` in a non-final stage. The final stage is pinned, so the multi-stage rules should NOT fire. |
| `secrets-in-env.Dockerfile` | Three secret-named `ENV` rows; `dkr-no-secrets-in-env` should fire once per row. |
| `add-remote.Dockerfile` | `ADD https://...`; `dkr-no-add-remote` should fire once. |
| `no-healthcheck.Dockerfile` | Baseline for the not-yet-implemented `dkr-healthcheck-defined` rule (zero findings until the rule is reviewed in). |

The runtime harness lives in `evals/benchmarks/scanner-eval.py`.
