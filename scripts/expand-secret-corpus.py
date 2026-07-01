#!/usr/bin/env python3
"""Expand the secret-detection test corpus to >=100 TP + >=100 TN.

Reads the curated entries already in skills/secret-detection/tests/corpus.json
and appends a *derived* block of mechanically-generated fixtures whose
expected outcome is fully determined by the secret pattern set itself —
i.e. each row maps 1:1 onto a real published vendor token format
(documented in the corresponding `references` field on the pattern in
skills/secret-detection/rules/dlp_patterns.json).

The script is idempotent: it strips any prior derived block tagged with
`source = "derived-expand-corpus"` before re-emitting, and every derived
fixture is built from deterministic byte cycles (no `secrets` / `random`
calls), so re-running produces byte-identical text and IDs for the
derived block. Curated fixtures (no `source`, or
`source != "derived-expand-corpus"`) are preserved by *parsed value*:
their `text` strings round-trip through `json.loads` unchanged, but
their on-disk \\uXXXX escape sequences may be re-canonicalised by the
defang pass (e.g. \\u0053\\u004b collapses to \\u0053K since the defang
rules only escape the leading byte of each token shape).

Token shape sources (every TP row below cites at least one):
  - AWS Access Key ID format: 'AKIA' + 16 base32 chars
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
  - GitHub PAT classic: 'ghp_' + 36 [A-Za-z0-9] chars
    https://github.blog/changelog/2021-03-31-authentication-token-format-updates/
  - GitHub fine-grained PAT: 'github_pat_' + 22 base62 + '_' + 59 base62
    https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
  - Slack tokens (xoxb-, xoxa-, xoxp-, xapp-)
    https://api.slack.com/authentication/token-types
  - Stripe live secret: 'sk_live_' + 24 [A-Za-z0-9]
    https://docs.stripe.com/keys
  - Twilio API Key SID: 'SK' + 32 hex
    https://www.twilio.com/docs/iam/api-keys
  - SendGrid: 'SG.' + 22 + '.' + 43
    https://docs.sendgrid.com/api-reference
  - Anthropic: 'sk-ant-api03-' + 95 base62/_-
    https://docs.anthropic.com/en/api/getting-started
  - OpenAI legacy: 'sk-' + 48 base62
    https://platform.openai.com/docs/api-reference/authentication
  - Discord webhook: discord.com/api/webhooks/<snowflake>/<70-char token>
    https://discord.com/developers/docs/resources/webhook
  - Datadog API: 32 hex chars adjacent to 'datadog' / 'dd_api_key'
    https://docs.datadoghq.com/account_management/api-app-keys/
  - PEM private key block header
    RFC 7468

Every TN row below carries a `reason` field justifying why the shape is
*not* a secret (commit SHA, CSS hex, UUID without hotword, etc.).

We never invent a new shape: every TP regex below maps to an existing
pattern entry in skills/secret-detection/rules/dlp_patterns.json.

AI authorship disclosure: drafted with AI assistance per AGENTS.md.
Token shapes are all from upstream vendor documentation linked above;
no shape is invented. The derived corpus is reviewable by running
`secure-vibe dev test secret-detection`.
"""

from __future__ import annotations

import json
import pathlib
import re
import string
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "skills/secret-detection/tests/corpus.json"


# The secret regexes only check SHAPE, not entropy. We deliberately use
# *low-entropy, deterministic* fillers (cycles through 0-9 a-f / 0-9
# a-z A-Z) so that synthetic fixtures DO NOT look like real high-
# entropy secrets to upstream scanners (GitHub Push Protection,
# gitleaks, TruffleHog). The trade-off is that two fixtures of the
# same generator produce the same body, so we vary the *position*
# in the cycle per call via a tiny counter to keep IDs distinct.
_HEX_CYCLE = "0123456789abcdef"
_B62_CYCLE = string.digits + string.ascii_lowercase + string.ascii_uppercase  # 0-9 a-z A-Z
_B62_OFFSET = [0]
_HEX_OFFSET = [0]


def b62(n: int, alphabet: str | None = None) -> str:
    """Return a length-n string. Deterministic, low-entropy. The
    optional alphabet argument constrains the output (e.g. an AWS
    key id is base32-uppercase). When alphabet is None we cycle
    through 0-9 a-z A-Z; otherwise we cycle through the supplied
    alphabet from a rotating offset so IDs remain distinct."""
    alpha = alphabet if alphabet is not None else _B62_CYCLE
    if not alpha:
        return ""
    off = _B62_OFFSET[0]
    _B62_OFFSET[0] = (off + 1) % len(alpha)
    return "".join(alpha[(off + i) % len(alpha)] for i in range(n))


def hex_str(n: int) -> str:
    off = _HEX_OFFSET[0]
    _HEX_OFFSET[0] = (off + 1) % len(_HEX_CYCLE)
    return "".join(_HEX_CYCLE[(off + i) % len(_HEX_CYCLE)] for i in range(n))


# Defang on-disk: replace the leading character of each well-known
# token shape with its \uXXXX escape. JSON parsers transparently
# resolve the escape so json.loads(file).['text'] still matches the
# regex — but on-disk grep / GitHub Push Protection / gitleaks-default
# do not, because they see a literal backslash-u sequence rather than
# the prefix character. The trick is borrowed from the curated
# fixtures already on main (e.g. "TWILIO_SK = \u0053\u004b...").
_DEFANG_RULES = [
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"\bASIA[A-Z0-9]{16}\b"),
    re.compile(r"\bSK[a-fA-F0-9]{32}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{18,}\.[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bghu_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bghs_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bghr_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
    re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"),
    re.compile(r"\bpk_live_[A-Za-z0-9]{24,}\b"),
    re.compile(r"\brk_live_[A-Za-z0-9]{24,}\b"),
    re.compile(r"\bdop_v1_[a-f0-9]{60,}\b"),
    re.compile(r"\bsbp_[a-f0-9]{36,}\b"),
    re.compile(r"\bxoxb-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bxoxa-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bxoxp-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bxoxs-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bsk-ant-api03-[A-Za-z0-9_-]{80,}\b"),
    re.compile(r"\bsk-proj-[A-Za-z0-9_-]{40,}\b"),
    # OpenAI legacy: bare `sk-` + 48 base62. Must come AFTER the more
    # specific `sk-ant-api03-` and `sk-proj-` rules so those win on
    # their own prefixes; the bare class is intentionally `[A-Za-z0-9]`
    # (no `-`/`_`) so it does not re-match `sk-ant-api03-...` or
    # `sk-proj-...` shapes.
    re.compile(r"\bsk-[A-Za-z0-9]{48,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bhvs\.[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{35,}\b"),
    re.compile(r"\bya29\.[A-Za-z0-9_-]{60,}\b"),
    re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
    re.compile(r"https://hooks\.slack\.com/workflows/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
    re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d{17,}/[A-Za-z0-9_-]{60,}"),
    re.compile(r"https://oauth2\.googleapis\.com/[A-Za-z0-9_-]+"),
]


def defang_text(text: str) -> str:
    """Run the file content through every defang rule, replacing the
    first byte of each match with a \\uXXXX JSON-escape."""
    for rx in _DEFANG_RULES:
        def repl(m: re.Match[str]) -> str:
            tok = m.group(0)
            return f"\\u{ord(tok[0]):04x}" + tok[1:]
        text = rx.sub(repl, text)
    return text


def make_tp_fixtures() -> list[dict]:
    """Return TP fixtures, each matching exactly one pattern in
    dlp_patterns.json. Every fixture includes a hotword in scope so
    patterns with require_hotword=true also fire."""
    out: list[dict] = []

    # AWS Access Key (20 chars: AKIA + 16 base32). Documentation
    # placeholder 'AKIAIOSFODNN7' is excluded via denylist so we steer
    # clear of it.
    for _ in range(15):
        key = "AKIA" + b62(16, string.ascii_uppercase + string.digits)
        if "EXAMPLE" in key or "AKIAIOSFODNN7" in key:
            continue
        out.append(
            {
                "id": f"tp-aws-{key[-6:].lower()}",
                "text": f"AWS_ACCESS_KEY_ID={key}",
                "expected": "detect",
                "expected_pattern": "AWS Access Key",
                "source": "derived-expand-corpus",
            }
        )

    # GitHub classic PAT (ghp_ + 36).
    for _ in range(10):
        tok = "ghp_" + b62(36)
        out.append(
            {
                "id": f"tp-github-pat-{tok[-6:].lower()}",
                "text": f"GITHUB_TOKEN={tok}",
                "expected": "detect",
                "expected_pattern": "GitHub Personal Access Token",
                "source": "derived-expand-corpus",
            }
        )

    # GitHub fine-grained PAT (github_pat_ + 22 + _ + 59).
    for _ in range(5):
        tok = "github_pat_" + b62(22) + "_" + b62(59)
        out.append(
            {
                "id": f"tp-github-fgpat-{tok[-6:].lower()}",
                "text": f"GITHUB_TOKEN={tok}",
                "expected": "detect",
                "expected_pattern": "GitHub Fine-Grained PAT",
                "source": "derived-expand-corpus",
            }
        )

    # Slack bot tokens. The two digit groups are deterministic 12-char
    # cycles through 0–9 (NOT `secrets.randbelow`), so re-running this
    # script produces byte-identical fixture text and IDs.
    for prefix in ("xoxb-", "xoxa-", "xoxp-", "xoxs-"):
        for _ in range(3):
            tok = f"{prefix}{b62(12, string.digits)}-{b62(12, string.digits)}-{b62(24)}"
            out.append(
                {
                    "id": f"tp-slack-{prefix.strip('-')}-{tok[-6:].lower()}",
                    "text": f"slack_token = '{tok}'",
                    "expected": "detect",
                    "expected_pattern": "Slack Token",
                    "source": "derived-expand-corpus",
                }
            )

    # Stripe live secret keys.
    for _ in range(10):
        tok = "sk_live_" + b62(24)
        out.append(
            {
                "id": f"tp-stripe-{tok[-6:].lower()}",
                "text": f"STRIPE_SECRET_KEY={tok}",
                "expected": "detect",
                "expected_pattern": "Stripe Live API Key",
                "source": "derived-expand-corpus",
            }
        )

    # Twilio API Key SIDs (SK + 32 hex).
    for _ in range(8):
        tok = "SK" + hex_str(32)
        out.append(
            {
                "id": f"tp-twilio-{tok[-6:].lower()}",
                "text": f"TWILIO_API_KEY={tok}",
                "expected": "detect",
                "expected_pattern": "Twilio API Key",
                "source": "derived-expand-corpus",
            }
        )

    # SendGrid (SG.22.43).
    for _ in range(8):
        tok = "SG." + b62(22) + "." + b62(43)
        out.append(
            {
                "id": f"tp-sendgrid-{tok[-6:].lower()}",
                "text": f"SENDGRID_API_KEY={tok}",
                "expected": "detect",
                "expected_pattern": "SendGrid API Key",
                "source": "derived-expand-corpus",
            }
        )

    # Anthropic (sk-ant-api03- + 95 chars).
    for _ in range(8):
        tok = "sk-ant-api03-" + b62(95, string.ascii_letters + string.digits + "_-")
        out.append(
            {
                "id": f"tp-anthropic-{tok[-6:].lower()}",
                "text": f"ANTHROPIC_API_KEY={tok}",
                "expected": "detect",
                "expected_pattern": "Anthropic API Key",
                "source": "derived-expand-corpus",
            }
        )

    # OpenAI legacy sk- + 48 alnum.
    for _ in range(8):
        tok = "sk-" + b62(48)
        out.append(
            {
                "id": f"tp-openai-legacy-{tok[-6:].lower()}",
                "text": f"OPENAI_API_KEY={tok}",
                "expected": "detect",
                "expected_pattern": "OpenAI API Key",
                "source": "derived-expand-corpus",
            }
        )

    # Datadog API key: 32 hex with hotword in scope.
    for _ in range(8):
        tok = hex_str(32)
        out.append(
            {
                "id": f"tp-datadog-{tok[-6:]}",
                "text": f"datadog_api_key = '{tok}'",
                "expected": "detect",
                "expected_pattern": "Datadog API Key",
                "source": "derived-expand-corpus",
            }
        )

    # Discord webhook (snowflake + 70-char token). Deterministic per
    # iteration: the global `b62` counter advances mod-10 and mod-62 in
    # lockstep here, which would otherwise yield only ~5 unique snowflake
    # / token combos across 8 iterations and produce byte-identical
    # fixture text. Seeding each iteration with the loop index `i`
    # multiplied by a small prime coprime with the alphabet size (7 for
    # the 10-digit cycle, 11 for the 62-char cycle) guarantees 8 distinct
    # webhooks while staying byte-stable across re-runs.
    for i in range(8):
        snowflake = "".join(string.digits[(7 * i + j) % 10] for j in range(18))
        tok = "".join(_B62_CYCLE[(11 * i + j) % 62] for j in range(70))
        url = f"https://discord.com/api/webhooks/{snowflake}/{tok}"
        out.append(
            {
                "id": f"tp-discord-{i:02d}-{snowflake[-4:]}",
                "text": f"DISCORD_WEBHOOK_URL={url}",
                "expected": "detect",
                "expected_pattern": "Discord Webhook URL",
                "source": "derived-expand-corpus",
            }
        )

    # Slack webhook.
    for _ in range(7):
        url = f"https://hooks.slack.com/services/T{b62(10, string.ascii_uppercase + string.digits)}/B{b62(10, string.ascii_uppercase + string.digits)}/{b62(24)}"
        out.append(
            {
                "id": f"tp-slack-webhook-{url[-4:]}",
                "text": f"SLACK_WEBHOOK={url}",
                "expected": "detect",
                "expected_pattern": "Slack Webhook URL",
                "source": "derived-expand-corpus",
            }
        )

    # PEM private-key block.
    for kind in ("RSA", "EC", "OPENSSH", "DSA"):
        out.append(
            {
                "id": f"tp-pem-{kind.lower()}",
                "text": (
                    f"-----BEGIN {kind} PRIVATE KEY-----\n"
                    f"{b62(64)}\n{b62(64)}\n{b62(40)}=\n"
                    f"-----END {kind} PRIVATE KEY-----"
                ),
                "expected": "detect",
                "expected_pattern": "Private Key Block",
                "source": "derived-expand-corpus",
            }
        )

    return out


def make_tn_fixtures() -> list[dict]:
    """Negative fixtures that closely RESEMBLE a secret in shape but
    must NOT be flagged. Each row carries a `reason` explaining why.
    Categories follow the catalog used by Yelp's `detect-secrets`
    documentation: docstrings, code samples, hashes, fingerprints,
    UUIDs, IDs, file paths."""
    out: list[dict] = []

    # CSS hex colors.
    for h in ("#abcdef", "#123456", "#fafbfc", "#deadbe", "#caffee", "#01234a", "#ff00aa"):
        out.append(
            {
                "id": f"tn-css-{h.lstrip('#')}",
                "text": f"color: {h};",
                "expected": "ignore",
                "reason": "CSS hex color, not a secret",
                "source": "derived-expand-corpus",
            }
        )

    # Git commit SHAs (40 hex) — no hotword.
    for _ in range(10):
        sha = hex_str(40)
        out.append(
            {
                "id": f"tn-git-sha-{sha[:6]}",
                "text": f"cherry-pick {sha} into main",
                "expected": "ignore",
                "reason": "git commit SHA without secret hotword",
                "source": "derived-expand-corpus",
            }
        )

    # 32-hex with no hotword (could be a hash, MAC, fingerprint).
    for _ in range(10):
        h = hex_str(32)
        out.append(
            {
                "id": f"tn-32hex-{h[:6]}",
                "text": f"md5 fingerprint = {h}",
                "expected": "ignore",
                "reason": "32-hex without secret hotword is a digest, not a key",
                "source": "derived-expand-corpus",
            }
        )

    # UUIDs not adjacent to credential hotwords.
    for _ in range(10):
        uid = f"{hex_str(8)}-{hex_str(4)}-{hex_str(4)}-{hex_str(4)}-{hex_str(12)}"
        out.append(
            {
                "id": f"tn-uuid-{uid[:8]}",
                "text": f"trace_id = '{uid}'",
                "expected": "ignore",
                "reason": "UUID with no credential hotword",
                "source": "derived-expand-corpus",
            }
        )

    # Documentation placeholders.
    # Placeholders below 20 base62 chars (Generic API Key regex floor)
    # so they do not trigger the regex floor that catches structured-but-
    # bogus strings. Longer placeholders are intentionally NOT included
    # here — the Generic API Key pattern is documented to flag them and
    # that flag is correct behaviour (a reviewer should still inspect a
    # 30-char ALL_CAPS string in code).
    placeholders = [
        ("YOUR_API_KEY_HERE", "common docs placeholder"),
        ("REPLACE_ME", "common docs placeholder"),
        ("XXXXXXXXXXXX", "ASCII-art placeholder"),
        ("<your-api-key>", "shell variable placeholder"),
        ("EXAMPLE_KEY", "documentation marker"),
        ("REDACTED", "redaction marker"),
        ("<secret>", "XML/markdown placeholder"),
        ("${API_KEY}", "shell variable interpolation"),
        ("{{api_key}}", "templating placeholder"),
        ("..stripped..", "log redaction"),
    ]
    for val, reason in placeholders:
        out.append(
            {
                "id": f"tn-placeholder-{val[:12].lower().replace(' ', '').replace('<', 'lt').replace('>', 'gt').replace('$', 'd').replace('{', 'ob').replace('}', 'cb')}",
                "text": f"api_key = \"{val}\"",
                "expected": "ignore",
                "reason": reason,
                "source": "derived-expand-corpus",
            }
        )

    # AWS docs example access keys (denylisted upstream).
    for ex in ("AKIAIOSFODNN7EXAMPLE", "AKIAEXAMPLEABCDEFGHI"):
        out.append(
            {
                "id": f"tn-aws-docs-{ex[-6:].lower()}",
                "text": f"aws_access_key_id = {ex}",
                "expected": "ignore",
                "reason": "AWS documentation placeholder",
                "source": "derived-expand-corpus",
            }
        )

    # Base64-encoded data with no key shape. Deterministic cycle
    # through the url-safe base64 alphabet (NOT `secrets.token_urlsafe`)
    # so re-running produces the same blob and ID per slot.
    _B64_ALPHABET = string.ascii_letters + string.digits + "-_"
    for _ in range(6):
        blob = b62(43, _B64_ALPHABET)
        out.append(
            {
                "id": f"tn-b64-{blob[:6].lower()}",
                "text": f"cache_token = '{blob}'  # rotated nightly",
                "expected": "ignore",
                "reason": "random base64 not adjacent to a known vendor prefix",
                "source": "derived-expand-corpus",
            }
        )

    # Long ASCII strings that look high-entropy but are docs/lorem/code.
    lorem_pieces = [
        "lorem ipsum dolor sit amet consectetur adipiscing elit sed do",
        "the quick brown fox jumps over the lazy dog 1234567890 abcdef",
        "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }",
        "select * from users where created_at > now() - interval '1 day'",
        "console.log('hello world from a test file')",
        "rev=abc123def456 # internal build tag",
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'/>",
        "ssh-rsa AAAAB3NzaC1yc2EA == comment-only",
    ]
    for i, t in enumerate(lorem_pieces):
        out.append(
            {
                "id": f"tn-prose-{i:02d}",
                "text": t,
                "expected": "ignore",
                "reason": "prose / code unrelated to credentials",
                "source": "derived-expand-corpus",
            }
        )

    # PEM CERTIFICATE blocks (NOT private keys). The 6-hex id slug is
    # generated by `hex_str(6)` (deterministic) rather than
    # `secrets.token_hex(3)` so re-running produces stable IDs.
    for _ in range(4):
        out.append(
            {
                "id": f"tn-pem-cert-{hex_str(6)}",
                "text": (
                    "-----BEGIN CERTIFICATE-----\n"
                    f"{b62(64)}\n{b62(64)}\n-----END CERTIFICATE-----"
                ),
                "expected": "ignore",
                "reason": "PEM CERTIFICATE block is a public cert, not a private key",
                "source": "derived-expand-corpus",
            }
        )

    # SHA-256 / SHA-1 digests (64 / 40 hex) — common in CI logs and
    # package lockfiles. Never a credential.
    for _ in range(8):
        d = hex_str(64)
        out.append(
            {
                "id": f"tn-sha256-{d[:6]}",
                "text": f"integrity: sha256-{d}",
                "expected": "ignore",
                "reason": "SHA-256 digest in a lockfile, not a credential",
                "source": "derived-expand-corpus",
            }
        )
    for _ in range(8):
        d = hex_str(40)
        out.append(
            {
                "id": f"tn-sha1-{d[:6]}",
                "text": f"sha1: {d}",
                "expected": "ignore",
                "reason": "SHA-1 digest, not a credential",
                "source": "derived-expand-corpus",
            }
        )

    # File paths and URLs that *contain* long opaque-looking segments
    # but are public identifiers, not secrets.
    paths = [
        "/cache/v3/files/aBcDeFgHiJ0123456789012345678901/object.bin",
        "https://cdn.example.com/static/dist/main.0123456789abcdef.js",
        "s3://public-bucket/release/2026-05-01/build-0123456789abcdef.tar",
        "image: docker.io/library/postgres@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "https://i.imgur.com/AbCdEfG.png",
        "ETag: \"686897696a7c876b7e\"",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Range: bytes=0-2147483647",
    ]
    for i, p in enumerate(paths):
        out.append(
            {
                "id": f"tn-pubid-{i:02d}",
                "text": p,
                "expected": "ignore",
                "reason": "public identifier in URL/path/header, not a credential",
                "source": "derived-expand-corpus",
            }
        )

    # Short tokens that fall below the pattern's minimum length.
    short = [
        ("ghp_short", "GitHub PAT prefix but too short"),
        ("sk-ant-api03-XXXX", "Anthropic prefix but length below threshold"),
        ("sk_live_short", "Stripe prefix but length below threshold"),
        ("SG.short.short", "SendGrid prefix but length below threshold"),
    ]
    for tok, reason in short:
        out.append(
            {
                "id": f"tn-short-{tok[:8].lower()}",
                "text": f"placeholder = '{tok}'",
                "expected": "ignore",
                "reason": reason,
                "source": "derived-expand-corpus",
            }
        )

    return out


def main() -> int:
    raw = json.loads(CORPUS.read_text())
    curated = [
        fx
        for fx in raw.get("fixtures", [])
        if fx.get("source") != "derived-expand-corpus"
    ]
    derived = make_tp_fixtures() + make_tn_fixtures()
    # Stable-sort within each group: curated first (preserves human
    # order); derived sorted by id for a deterministic on-disk shape.
    derived.sort(key=lambda fx: fx["id"])
    raw["fixtures"] = curated + derived
    text = json.dumps(raw, indent=2)
    text = defang_text(text)
    CORPUS.write_text(text + "\n")
    tp = sum(1 for f in raw["fixtures"] if f["expected"] == "detect")
    tn = sum(1 for f in raw["fixtures"] if f["expected"] == "ignore")
    print(
        f"corpus refreshed: {tp} TP + {tn} TN = {tp + tn} total "
        f"(curated={len(curated)}, derived={len(derived)})"
    )
    if tp < 100 or tn < 100:
        print("WARN: target was >=100 TP and >=100 TN; review derived fixture generation", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
