#!/usr/bin/env python3
"""Run scanner fixtures through `secure-vibe mcp` and score the findings.

This is the generic harness behind eval steps 4–6 of `run-evals.sh`.
Each fixture pairs an input file (lockfile, workflow YAML, Dockerfile)
with an `expected.json` describing the expected findings. We drive
the scanner over JSON-RPC against the locally built `secure-vibe mcp`
binary, then compute precision / recall against the expectation set.

Why MCP rather than a CLI?
--------------------------
`secure-vibe` does not yet expose `scan-*` subcommands. Building a
dedicated CLI just for evals would duplicate the MCP tool surface,
so we ride the existing protocol instead. One persistent subprocess
serves the whole fixture pass, so the per-fixture overhead is just
two JSON-RPC round trips.

Output
------
- Prints a per-fixture pass/fail line.
- Writes a Markdown report to --out (default
  `evals/baselines/scanner-eval-static.md`) so the precision/recall
  table is diffable in a PR.
- Returns exit code 0 on full pass, 1 on any miss.

Usage
-----
    python3 evals/benchmarks/scanner-eval.py \\
        --secure-vibe ./secure-vibe \\
        --out evals/baselines/scanner-eval-static.md

The `--scanner` flag restricts the run to one scanner ("dependencies",
"github_actions", "dockerfile") — useful when iterating locally.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "evals" / "baselines" / "scanner-eval-static.md"

# Maps a scanner name to the MCP tool method, the fixture directory,
# the file extension we treat as the "input" file, and the keys we
# pull from the expected.json shape to identify a finding.
SCANNERS: dict[str, dict[str, Any]] = {
    "dependencies": {
        "tool": "scan_dependencies",
        "dir": REPO_ROOT / "evals" / "fixtures" / "dependency-choice",
        "expected_filename": "expected.json",
        "input_globs": (
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "requirements.txt",
            "Pipfile.lock",
            "poetry.lock",
            "go.sum",
            "Cargo.lock",
            "Gemfile.lock",
            "pom.xml",
            "gradle.lockfile",
            "packages.lock.json",
            "composer.lock",
            "Package.resolved",
            "pubspec.lock",
        ),
        "key": lambda f: (
            (f.get("ecosystem") or "").lower(),
            (f.get("package") or "").lower(),
            (f.get("category") or "malicious").lower()
            if "kind" not in f
            else f.get("kind", "").lower(),
        ),
        "actual_key": lambda f: (
            (f.get("ecosystem") or "").lower(),
            (f.get("package") or "").lower(),
            _category_to_kind(f.get("category", "")),
        ),
    },
    "github_actions": {
        "tool": "scan_github_actions",
        "dir": REPO_ROOT / "evals" / "fixtures" / "cicd-hardening",
        "expected_suffix": ".expected.json",
        "input_suffix": ".yml",
        "key": lambda f: ((f.get("rule") or f.get("rule_id") or "").lower(),),
        "actual_key": lambda f: ((f.get("rule_id") or "").lower(),),
    },
    "dockerfile": {
        "tool": "scan_dockerfile",
        "dir": REPO_ROOT / "evals" / "fixtures" / "docker-hardening",
        "expected_suffix": ".expected.json",
        "input_suffix": ".Dockerfile",
        "key": lambda f: ((f.get("rule") or f.get("rule_id") or "").lower(),),
        "actual_key": lambda f: ((f.get("rule_id") or "").lower(),),
    },
}


def _category_to_kind(cat: str) -> str:
    """Map a DependencyFinding.category to the eval-fixture 'kind' field.

    The scanner emits categories like "malicious-package", "typosquat",
    "cve-pattern", and "osv-advisory". The eval fixtures use the
    shorter "malicious" / "typosquat" / "cve" / "osv" labels, so we
    normalise on lookup rather than rewriting every fixture.
    """
    cat = (cat or "").lower()
    if cat in ("malicious-package", "malicious", "malicious_package"):
        return "malicious"
    if cat in ("typosquat", "potential-typosquat"):
        return "typosquat"
    if cat in ("cve-pattern", "cve"):
        return "cve"
    if cat in ("osv-advisory", "osv"):
        return "osv"
    return cat


@dataclass
class FixtureResult:
    scanner: str
    fixture: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    missing: list[str]
    unexpected: list[str]


class MCPClient:
    """Minimal JSON-RPC client over the secure-vibe mcp stdio protocol."""

    def __init__(self, binary: pathlib.Path, allowed_roots: list[pathlib.Path]):
        # The MCP server is the `mcp` subcommand of the unified secure-vibe binary.
        cmd = [str(binary), "mcp", "--allowed-roots", ",".join(str(p) for p in allowed_roots)]
        # We deliberately do NOT pipe stderr — secure-vibe writes its
        # request log there, and surfacing it during the eval makes
        # the failure mode obvious when something goes wrong.
        self.proc = subprocess.Popen(  # noqa: S603 — trusted binary path
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._id = 0
        self._send(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "scanner-eval.py", "version": "0.1"},
                },
            }
        )
        self._recv()  # discard initialize response

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _recv(self) -> dict:
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("secure-vibe mcp closed stdout unexpectedly")
        return json.loads(line)

    def call(self, tool: str, arguments: dict) -> dict:
        self._send(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            }
        )
        resp = self._recv()
        if "error" in resp:
            raise RuntimeError(f"{tool}: {resp['error']}")
        # The MCP server returns {"content": [{"type": "text", "text": "<json>"}]}.
        content = resp.get("result", {}).get("content") or []
        if not content:
            return {}
        try:
            return json.loads(content[0]["text"])
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError(f"{tool}: invalid response: {exc}; raw={content}")

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        finally:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _iter_fixtures(scanner: str) -> Iterable[tuple[pathlib.Path, pathlib.Path]]:
    """Yield (input_path, expected_path) pairs for a scanner.

    The fixture layout differs between scanners:
      * dependencies — one subdir per fixture with `expected.json`
        and a lockfile.
      * github_actions / dockerfile — flat directory with paired
        `<name>.<input_suffix>` and `<name>.expected.json`.
    """
    cfg = SCANNERS[scanner]
    root: pathlib.Path = cfg["dir"]
    if not root.exists():
        return
    if "expected_filename" in cfg:
        # Per-subdir layout (dependency-choice).
        for sub in sorted(p for p in root.iterdir() if p.is_dir()):
            exp = sub / cfg["expected_filename"]
            if not exp.exists():
                continue
            input_path = None
            for name in cfg["input_globs"]:
                cand = sub / name
                if cand.exists():
                    input_path = cand
                    break
            if input_path is None:
                continue
            yield input_path, exp
        return
    # Paired-file layout (cicd-hardening, docker-hardening).
    suffix = cfg["expected_suffix"]
    in_suffix = cfg["input_suffix"]
    for exp in sorted(root.glob(f"*{suffix}")):
        base = exp.name[: -len(suffix)]
        inp = root / f"{base}{in_suffix}"
        if inp.exists():
            yield inp, exp


def _score(
    scanner: str,
    expected: list[dict],
    findings: list[dict],
) -> tuple[int, int, int, list[str], list[str]]:
    cfg = SCANNERS[scanner]
    exp_keys = [cfg["key"](e) for e in expected]
    actual_keys = [cfg["actual_key"](f) for f in findings]
    matched_actual = [False] * len(actual_keys)
    tp = 0
    missing: list[str] = []
    for ek in exp_keys:
        hit = False
        for i, ak in enumerate(actual_keys):
            if matched_actual[i]:
                continue
            if ak == ek:
                matched_actual[i] = True
                tp += 1
                hit = True
                break
        if not hit:
            missing.append("/".join(str(s) for s in ek))
    fp = sum(1 for m in matched_actual if not m)
    fn = len(missing)
    unexpected = [
        "/".join(str(s) for s in actual_keys[i])
        for i, m in enumerate(matched_actual)
        if not m
    ]
    return tp, fp, fn, missing, unexpected


class _SkipFixture(Exception):
    """Raised when a fixture cannot be evaluated end-to-end (e.g. its
    input file isn't a format the scanner accepts). The caller skips
    the fixture rather than counting it as a failure."""


def _run_scanner(
    client: MCPClient, scanner: str, input_path: pathlib.Path
) -> list[dict]:
    cfg = SCANNERS[scanner]
    try:
        res = client.call(cfg["tool"], {"file_path": str(input_path)})
    except RuntimeError as exc:
        msg = str(exc)
        if "unrecognised lockfile" in msg or "unknown format" in msg:
            # Some legacy fixtures ship a `package.json` rather than a
            # lockfile. The scanner deliberately rejects loose manifests
            # because they don't pin a version; we skip the fixture
            # instead of forcing it into precision/recall numbers.
            raise _SkipFixture(msg) from exc
        raise
    return res.get("findings") or []


def _build_secure_vibe() -> pathlib.Path:
    """Locate or build the secure-vibe binary (the MCP server is `secure-vibe mcp`)."""
    bin_path = REPO_ROOT / "secure-vibe"
    if bin_path.exists() and os.access(bin_path, os.X_OK):
        return bin_path
    found = shutil.which("secure-vibe")
    if found:
        return pathlib.Path(found)
    # Build into the repo root so subsequent runs reuse it.
    print("    building secure-vibe ...")
    subprocess.run(
        ["go", "build", "-o", str(bin_path), "./cmd/secure-vibe"],
        cwd=REPO_ROOT,
        check=True,
    )
    return bin_path


def _render_report(rows: list[FixtureResult]) -> str:
    by_scanner: dict[str, list[FixtureResult]] = defaultdict(list)
    for r in rows:
        by_scanner[r.scanner].append(r)
    lines: list[str] = []
    lines.append("# Scanner eval — precision/recall")
    lines.append("")
    lines.append(
        "Auto-generated by `evals/benchmarks/scanner-eval.py`. Re-run after"
        " any change to scanner code or fixtures; CI fails when this file"
        " drifts from the harness output."
    )
    lines.append("")
    if not rows:
        lines.append("_No fixtures were evaluated._")
        return "\n".join(lines) + "\n"

    for scanner, items in sorted(by_scanner.items()):
        tp = sum(i.tp for i in items)
        fp = sum(i.fp for i in items)
        fn = sum(i.fn for i in items)
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / (tp + fn) if (tp + fn) else 1.0
        lines.append(f"## `{scanner}`")
        lines.append("")
        lines.append(f"- Fixtures: **{len(items)}**")
        lines.append(f"- True positives: **{tp}**")
        lines.append(f"- False positives: **{fp}**")
        lines.append(f"- False negatives: **{fn}**")
        lines.append(f"- Precision: **{prec * 100:.1f}%**")
        lines.append(f"- Recall: **{rec * 100:.1f}%**")
        lines.append("")
        lines.append("| Fixture | TP | FP | FN | Precision | Recall |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for it in items:
            lines.append(
                "| {f} | {tp} | {fp} | {fn} | {p:.1%} | {r:.1%} |".format(
                    f=it.fixture,
                    tp=it.tp,
                    fp=it.fp,
                    fn=it.fn,
                    p=it.precision,
                    r=it.recall,
                )
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def _evaluate(
    scanners: list[str], secure_vibe: pathlib.Path, verbose: bool
) -> tuple[list[FixtureResult], list[tuple[str, str, str]]]:
    # Allow the MCP scanner to read every fixture directory + the repo
    # root (some fixtures reference shared data, e.g. cve_patterns.json).
    allowed_roots = [REPO_ROOT]
    for s in scanners:
        d = SCANNERS[s]["dir"]
        if d.exists():
            allowed_roots.append(d)
    client = MCPClient(secure_vibe, allowed_roots)
    rows: list[FixtureResult] = []
    # (scanner, fixture-rel-path, reason) for fixtures the harness could
    # not evaluate. Returned alongside `rows` so callers can surface them
    # rather than silently dropping them from precision / recall counts.
    skipped: list[tuple[str, str, str]] = []
    try:
        for scanner in scanners:
            for input_path, expected_path in _iter_fixtures(scanner):
                expected = (
                    json.loads(expected_path.read_text()).get("expected_findings") or []
                )
                try:
                    findings = _run_scanner(client, scanner, input_path)
                except _SkipFixture as exc:
                    rel = input_path.relative_to(REPO_ROOT).as_posix()
                    skipped.append((scanner, rel, str(exc)))
                    if verbose:
                        print(f"    [{scanner}] SKIP {rel}: {exc}")
                    continue
                tp, fp, fn, missing, unexpected = _score(scanner, expected, findings)
                precision = tp / (tp + fp) if (tp + fp) else 1.0
                recall = tp / (tp + fn) if (tp + fn) else 1.0
                rel = input_path.relative_to(REPO_ROOT).as_posix()
                rows.append(
                    FixtureResult(
                        scanner=scanner,
                        fixture=rel,
                        tp=tp,
                        fp=fp,
                        fn=fn,
                        precision=precision,
                        recall=recall,
                        missing=missing,
                        unexpected=unexpected,
                    )
                )
                status = "OK" if (fn == 0) else "MISS"
                if verbose or fn > 0:
                    print(
                        f"    [{scanner}] {status} {rel}: tp={tp} fp={fp} fn={fn}"
                    )
                    if missing:
                        print(f"        missing: {missing}")
    finally:
        client.close()
    return rows, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scanner",
        action="append",
        choices=sorted(SCANNERS.keys()),
        default=None,
        help="Restrict the run to one scanner. May be repeated.",
    )
    parser.add_argument(
        "--secure-vibe",
        default="",
        help="Path to secure-vibe mcp binary (default: locate or build at repo root).",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUT),
        help="Output Markdown report path.",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if any fixture has FN > 0 (default behaviour). "
        "Pass --no-check to compute the report without failing.",
    )
    parser.add_argument("--no-check", dest="check", action="store_false")
    parser.set_defaults(check=True)
    parser.add_argument(
        "--strict-skips",
        action="store_true",
        help="Treat any skipped fixture as a failure (exit non-zero). "
        "Useful for CI runs where silent drops should not be allowed.",
    )
    args = parser.parse_args(argv)

    scanners = args.scanner or sorted(SCANNERS.keys())
    binary = (
        pathlib.Path(args.secure_vibe).resolve()
        if args.secure_vibe
        else _build_secure_vibe()
    )
    if not binary.exists():
        print(f"secure-vibe mcp binary not found: {binary}", file=sys.stderr)
        return 1

    rows, skipped = _evaluate(scanners, binary, args.verbose)
    report = _render_report(rows)

    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    print(f"==> wrote {out_path}")

    if skipped:
        # Always surface skipped fixtures, even when --verbose is off — a
        # silent drop is exactly the kind of thing that hides a regression
        # (e.g. a fixture stops being recognised by the parser and no longer
        # contributes to precision / recall). The detail line above only
        # prints under --verbose.
        print(
            f"warn: {len(skipped)} fixture(s) skipped and excluded from "
            f"precision / recall:",
            file=sys.stderr,
        )
        for scanner, rel, reason in skipped:
            print(f"  [{scanner}] {rel}: {reason}", file=sys.stderr)

    failures = [r for r in rows if r.fn > 0]
    if args.check and failures:
        print(f"FAIL: {len(failures)} fixture(s) had missing expected findings")
        return 1
    if args.strict_skips and skipped:
        print(
            f"FAIL: --strict-skips and {len(skipped)} fixture(s) skipped",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
