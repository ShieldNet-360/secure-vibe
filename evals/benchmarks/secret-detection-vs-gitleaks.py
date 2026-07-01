#!/usr/bin/env python3
"""Precision/recall benchmark for the `secret-detection` skill.

Reads skills/secret-detection/tests/corpus.json (the source-of-truth
fixture set) and evaluates two engines against it:

  1. secure-vibe secret-detection patterns (the `type: secret_pattern` entries of
     skills/secret-detection/checklists/secret_detection.yaml), via the
     same regex+hotword logic the `secure-vibe dev test` runner uses.
  2. (optional) gitleaks v8 with its default ruleset — the most
     widely-deployed open-source secret scanner. The script will
     auto-detect the `gitleaks` binary on $PATH and run it in
     `--no-git --report-format json` mode against a temp file per
     fixture. If gitleaks is not installed the gitleaks columns are
     reported as "n/a" but the secure-vibe numbers still print.

Output: a Markdown table with TP/FP/FN/TN counts, precision, recall,
and F1 for each engine. Designed to be human-reviewable and to live
in a PR description.

Why not call the existing `secure-vibe dev test` Go binary? `test`
exits non-zero on the first failed fixture and does not emit a
machine-readable confusion matrix. Re-implementing the (small)
regex+hotword matcher in Python here keeps the harness dependency-
free and lets us compute precision/recall across every fixture in
one pass.

The matching logic is a faithful re-implementation of
cmd/secure-vibe/cmd/test.go (see the `matchAny`, `hotwordNear`,
`denylisted` functions and the `rulePatternEntry`/`loadRulePatterns`
loader there). Like that runner, it reads the `type: secret_pattern`
entries from skills/secret-detection/checklists/secret_detection.yaml
and applies only regex + hotword + denylist gating — NOT the score /
entropy fields, which the `secure-vibe dev test` corpus runner also
ignores (see test.go's note on rulePatternEntry). Because the corpus
runner is the source of truth, a faithful mirror MUST reproduce its
verdicts: `secure-vibe dev test secret-detection` passing with 0 failures
implies this harness reports 0 false positives AND 0 false negatives in
the secure-vibe column. A divergence there is a bug to flag.

AI authorship disclosure: this harness was drafted with AI assistance
per AGENTS.md.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
CORPUS = ROOT / "skills/secret-detection/tests/corpus.json"
# secret rules migrated from rules/dlp_patterns.json to a YAML checklist in
# fccc44f (PR #7); mirror cmd/secure-vibe/cmd/test.go and read the
# `type: secret_pattern` entries straight from the checklist so the two
# stay in lockstep.
PATTERNS = ROOT / "skills/secret-detection/checklists/secret_detection.yaml"


@dataclass
class CompiledPattern:
    name: str
    regex: re.Pattern[str]
    hotwords: list[str]
    hotword_window: int
    require_hotword: bool
    denylist: list[str]


def load_patterns() -> list[CompiledPattern]:
    """Compile the `type: secret_pattern` entries from the secret-detection
    YAML checklist, mirroring cmd/secure-vibe/cmd/test.go:loadRulePatterns.
    Only regex + hotword + denylist fields are read; score_weight, entropy_min
    and hotword_boost are intentionally ignored — the Go corpus runner ignores
    them too, so this keeps the binary detect/ignore verdict identical."""
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - explicit user message
        raise SystemExit(
            "PyYAML is required to read the secret-detection checklist; "
            "run `pip install pyyaml`"
        ) from exc
    raw = yaml.safe_load(PATTERNS.read_text())
    out: list[CompiledPattern] = []
    for c in raw.get("checks") or []:
        if c.get("type") != "secret_pattern":
            continue
        try:
            rx = re.compile(c["pattern"])
        except re.error:
            # Mirror the Go runner's behaviour: skip patterns that
            # don't compile cleanly under this engine.
            continue
        out.append(
            CompiledPattern(
                name=c.get("title") or c.get("id") or "",
                regex=rx,
                hotwords=c.get("hotwords") or [],
                hotword_window=c.get("hotword_window") or 80,
                require_hotword=bool(c.get("require_hotword")),
                denylist=c.get("denylist_substrings") or [],
            )
        )
    if not out:
        # Fail loudly: a renamed checklist or a schema change that drops
        # every `type: secret_pattern` entry would otherwise score every
        # fixture as a false negative and silently report 0% recall — the
        # exact silent breakage this loader was rewritten to end.
        raise SystemExit(
            f"no secret_pattern entries loaded from {PATTERNS} — "
            "the checklist path or schema changed; this harness is stale"
        )
    return out


def hotword_near(text: str, span: tuple[int, int], hotwords: list[str], window: int) -> bool:
    """Mirrors Go's hotwordNear (cmd/secure-vibe/cmd/test.go:252) which
    measures the window in *UTF-8 bytes*, not characters. Python's `re`
    returns character spans, so we convert to byte offsets before applying
    the window. The slice is then decoded with ``errors='replace'`` to
    survive partial multi-byte sequences at the window edges — Go's
    ``string[i:j]`` has the same byte-truncation semantics. For the current
    ASCII-only corpus the character and byte arithmetic agree, but this
    keeps the two implementations equivalent under future non-ASCII
    fixtures."""
    if window <= 0:
        window = 80
    text_b = text.encode("utf-8")
    start_b = len(text[: span[0]].encode("utf-8"))
    end_b = len(text[: span[1]].encode("utf-8"))
    win_start = max(0, start_b - window)
    win_end = min(len(text_b), end_b + window)
    region = text_b[win_start:win_end].decode("utf-8", errors="replace").lower()
    return any(h.lower() in region for h in hotwords)


def denylisted(match_text: str, denylist: list[str]) -> bool:
    lower = match_text.lower()
    return any(sub.lower() in lower for sub in denylist)


def skills_match(text: str, patterns: list[CompiledPattern]) -> bool:
    """Returns True iff at least one pattern fires on `text`,
    respecting hotwords and denylists.

    Mirrors Go's ``matchAny`` (cmd/secure-vibe/cmd/test.go:196) which
    iterates every pattern and tracks the *last non-Generic* match as the
    "best". The binary precision/recall outcome is the same whether we
    return on the first match or iterate everything, but the Go-aligned
    walk preserves the selection invariant for any future extension that
    surfaces the matched pattern name out of this harness."""
    best_name = ""
    for p in patterns:
        m = p.regex.search(text)
        if not m:
            continue
        if denylisted(m.group(0), p.denylist):
            continue
        if p.require_hotword or p.hotwords:
            if not hotword_near(text, m.span(), p.hotwords, p.hotword_window):
                if p.require_hotword:
                    continue
        is_generic = p.name.startswith("Generic ")
        if best_name == "" or not is_generic:
            best_name = p.name
    return best_name != ""


def gitleaks_match(text: str, binary: str) -> bool:
    """Run gitleaks once per fixture. Returns True iff gitleaks finds
    at least one leak. Slow (~50–100ms per call); only use when the
    binary is present and the user opted in."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write(text)
        tmp.flush()
        report = tmp.name + ".json"
    try:
        try:
            subprocess.run(
                [
                    binary,
                    "detect",
                    "--no-git",
                    "--source",
                    tmp.name,
                    "--report-format",
                    "json",
                    "--report-path",
                    report,
                    "--exit-code",
                    "0",
                    "--no-banner",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        try:
            leaks = json.loads(pathlib.Path(report).read_text() or "[]")
        except (FileNotFoundError, json.JSONDecodeError):
            leaks = []
        return bool(leaks)
    finally:
        # Clean up BOTH the source tempfile AND the gitleaks report on
        # every exit path — including the early returns triggered by
        # FileNotFoundError / TimeoutExpired, which previously left a
        # partial `*.json` report behind on timeout.
        pathlib.Path(tmp.name).unlink(missing_ok=True)
        pathlib.Path(report).unlink(missing_ok=True)


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else math.nan

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else math.nan

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if math.isnan(p) or math.isnan(r) or (p + r) == 0:
            return math.nan
        return 2 * p * r / (p + r)


def score(fixtures: Iterable[dict], predict) -> Counts:
    c = Counts()
    for fx in fixtures:
        want = fx["expected"] == "detect"
        got = predict(fx["text"])
        if want and got:
            c.tp += 1
        elif want and not got:
            c.fn += 1
        elif (not want) and got:
            c.fp += 1
        else:
            c.tn += 1
    return c


def fmt_pct(x: float) -> str:
    return "n/a" if math.isnan(x) else f"{x * 100:.1f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--gitleaks",
        default="auto",
        help="Path to gitleaks binary (default: auto-detect on $PATH; "
        "pass 'skip' to disable gitleaks even if installed).",
    )
    ap.add_argument(
        "--out",
        default="-",
        help="Output path for the markdown report (default: stdout).",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Gate mode: exit non-zero if the secure-vibe column regresses "
        "(any false positive or false negative on the corpus). Keyless and "
        "fast — skips gitleaks. Use in CI so a future break in this harness "
        "(a renamed checklist, a drifted matcher) fails loudly instead of "
        "silently reporting bogus numbers.",
    )
    args = ap.parse_args()

    corpus = json.loads(CORPUS.read_text())
    fixtures = corpus["fixtures"]
    patterns = load_patterns()

    if args.check:
        # The corpus is the skill's quality floor; a faithful harness must
        # reproduce secure-vibe's 0-failure verdict. Gate on that and exit
        # before the (slow, key/binary-dependent) gitleaks pass and report
        # rendering — none of which the gate needs.
        c = score(fixtures, lambda t: skills_match(t, patterns))
        if c.fp or c.fn:
            sys.stderr.write(
                f"CHECK FAILED: secure-vibe column regressed — "
                f"{c.fp} false positive(s), {c.fn} false negative(s) on "
                f"{len(fixtures)} fixtures. The harness has drifted from the "
                f"secret-detection engine (`secure-vibe dev test secret-detection` "
                f"is the source of truth).\n"
            )
            return 1
        sys.stderr.write(
            f"CHECK OK: secure-vibe {c.tp} TP / {c.fp} FP / {c.fn} FN / "
            f"{c.tn} TN — 100% precision & recall on the corpus.\n"
        )
        return 0

    gitleaks_bin: str | None = None
    if args.gitleaks == "auto":
        gitleaks_bin = shutil.which("gitleaks")
    elif args.gitleaks != "skip":
        gitleaks_bin = args.gitleaks if shutil.which(args.gitleaks) else None

    skills_counts = score(fixtures, lambda t: skills_match(t, patterns))
    if gitleaks_bin:
        gitleaks_counts: Counts | None = score(
            fixtures, lambda t: gitleaks_match(t, gitleaks_bin)
        )
    else:
        gitleaks_counts = None

    tp = sum(1 for f in fixtures if f["expected"] == "detect")
    tn = sum(1 for f in fixtures if f["expected"] == "ignore")

    lines: list[str] = []
    lines.append("# secret-detection benchmark")
    lines.append("")
    lines.append(f"Corpus: `{CORPUS.relative_to(ROOT)}` ({len(fixtures)} fixtures: {tp} TP, {tn} TN)")
    lines.append("")
    lines.append(
        "> **Honesty note.** The secure-vibe secret rule set is *tuned*\n"
        "> against this corpus — perfect or near-perfect numbers here\n"
        "> only show the rules cover their own test bed, not that they\n"
        "> will generalize. The gitleaks column is the more interesting\n"
        "> signal: it measures how a popular general-purpose ruleset\n"
        "> scores on shapes that the secure-vibe claims to handle.\n"
        "> Treat regressions in the gitleaks column as expected when\n"
        "> we add a new pattern that gitleaks does not know about, and\n"
        "> regressions in the secure-vibe column as a hard fail.\n"
    )
    lines.append("| engine | TP | FP | FN | TN | precision | recall | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    lines.append(
        "| secure-vibe secret-detection patterns | "
        f"{skills_counts.tp} | {skills_counts.fp} | {skills_counts.fn} | {skills_counts.tn} | "
        f"{fmt_pct(skills_counts.precision)} | {fmt_pct(skills_counts.recall)} | "
        f"{fmt_pct(skills_counts.f1)} |"
    )
    if gitleaks_counts is not None:
        # Strip the absolute path of the gitleaks binary out of the
        # report — only its basename. The full path varies per
        # contributor (`/home/ubuntu/go/bin/gitleaks` vs
        # `/usr/local/bin/gitleaks` vs `~/go/bin/gitleaks` …) and would
        # otherwise churn the committed baseline on every run.
        gitleaks_name = pathlib.Path(gitleaks_bin).name if gitleaks_bin else "gitleaks"
        lines.append(
            f"| gitleaks (default ruleset, `{gitleaks_name}`) | "
            f"{gitleaks_counts.tp} | {gitleaks_counts.fp} | {gitleaks_counts.fn} | {gitleaks_counts.tn} | "
            f"{fmt_pct(gitleaks_counts.precision)} | {fmt_pct(gitleaks_counts.recall)} | "
            f"{fmt_pct(gitleaks_counts.f1)} |"
        )
    else:
        lines.append(
            "| gitleaks (default ruleset) | n/a | n/a | n/a | n/a | n/a | n/a | n/a |"
        )
        lines.append("")
        lines.append("> gitleaks not installed; pass `--gitleaks /path/to/gitleaks` to compare. ")
        lines.append("> Install via `go install github.com/gitleaks/gitleaks/v8@latest`.")

    body = "\n".join(lines) + "\n"
    if args.out == "-":
        sys.stdout.write(body)
    else:
        pathlib.Path(args.out).write_text(body)
        sys.stderr.write(f"wrote {args.out}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
