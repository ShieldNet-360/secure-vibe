# Frequently asked questions

Quick, honest answers to the questions people ask most about SecureVibe.

### Isn't this just another scanner?

No. SecureVibe is **prevention-first**: it ships signed security **skills** that go into your AI coding assistant's context so it writes secure code at *generation time* — "left of the cursor." The 4 deterministic scanners are the **backstop**, not the product.

Most tools sit *right* of the cursor: they wait for code to exist, then flag it. SecureVibe tries to stop the insecure pattern from being written in the first place, and only then catches what slipped through.

!!! tip "Compare in detail"
    See [SecureVibe vs. scanners](concepts/comparison.md) for a side-by-side of the prevention lane versus detection-only tooling.

### Does it send my code anywhere?

No. SecureVibe is **fully offline**:

- No telemetry.
- No cloud dependency.
- No API key required.
- The CLI (`secure-vibe`) and MCP server (`secure-vibe mcp`) both run **entirely on your machine**.

Your code never leaves your environment. This also makes SecureVibe usable in air-gapped setups.

### What does it actually detect?

Four **deterministic** scanners:

| Scanner | Catches |
|---|---|
| Secrets | Hardcoded keys, tokens, credentials (83 detection patterns) |
| Dependencies | Malicious / typosquatted packages, known CVEs, OSV advisories |
| Dockerfile | Insecure container build patterns |
| GitHub Actions | Risky CI/CD workflow patterns |

!!! warning "Narrow by design"
    Detection is **narrow on purpose** — high precision over broad coverage. SecureVibe is **not a general SAST** and does not replace one. It catches **known patterns** and **misses novel or semantic bugs**. That trade-off is intentional: prevention (the skills) is the primary lane; the scanners are a precise backstop.

### Which AI assistants does it work with?

Eight, via `secure-vibe init --tool <name>` (which writes that assistant's native config file) or by running the `secure-vibe mcp` MCP server:

- Claude Code
- Cursor
- GitHub Copilot
- Codex
- Windsurf
- Cline / OpenCode
- Antigravity
- Devin

```bash
# Example: set up Cursor
secure-vibe init --tool cursor

# Or wire up the MCP server in Claude Code
claude mcp add secure-vibe -- npx -y @shieldnet360/secure-vibe mcp
```

### Do I need an API key? Does it cost anything?

No and no. SecureVibe is **MIT-licensed, free, and offline** — no API key, no account, no metered billing for normal use.

!!! note "The one exception"
    The optional live-model **prevention-lift eval** can talk to a model, but even that doesn't *require* a paid key. You can run it:

    - keyless against a local model via Ollama,
    - on your existing Claude Code subscription (`--provider claude-cli`, no metered billing), or
    - with an API key if you prefer.

### How do I add a package the database doesn't know about?

Use the **LEARN loop**. Add the package locally and the gate will block it on the next run:

```bash
secure-vibe contribute add -p <package> -e <npm|pypi|...>
```

This writes a **signed** local overlay (`.secure-vibe/overlay.json`). You can keep it to yourself, commit it so your whole team picks it up, or submit it upstream so others benefit.

See the [Contributor guide](guides/contributor.md) for the full add → sign → share → import workflow.

### How do you keep the malicious-package data trustworthy?

Three things:

1. **Curated, web-cited entries only.** Every curated entry in the database links to a real, citable source. Nothing is fabricated.
2. **Exact-match lookups = zero false positives.** The data moat is precision: a hit means the package is genuinely the one cited, not a fuzzy guess.
3. **Signed updates.** `secure-vibe update --self` fetches a signed release manifest and verifies an **Ed25519 signature** *and* SHA-256 checksums against the embedded public key before atomically replacing the binary. Contribution overlays are signed too, and import is signature-gated.

### What are your benchmark numbers?

Two kinds of measurement, reported honestly:

**Deterministic scanner benchmarks** (solid, reproducible, CI-gated):

- **Secret scanner:** 100% precision / 100% recall vs. gitleaks at 92.4% / 65.9% (76.9 F1) — **on SecureVibe's own tuned corpus** ("on the shapes we tested"). The honest signal here is gitleaks' *recall gap*, not a universal win.
- **The 3 structured scanners** (dependencies / Dockerfile / GitHub Actions): 100% precision / recall on the committed eval corpus.

These are **prevention ground-truth on curated corpora — not a claim of universal detection.**

!!! warning "The prevention-lift number is deliberately withheld"
    SecureVibe also has a live-model **prevention-lift** methodology (does having the skills in context lower a model's insecure-output rate?). We **do not publish a prevention-lift percentage** yet, by choice. The fast default regex classifier mislabels secure-with-explanation output as insecure — when skills make a model write safe code *and* name the risk it avoided, the regex matches the warning text and scores it as a vulnerability. The aggregate is therefore an artifact, not a signal. Trustworthy figures require LLM-judge scoring, which is the prerequisite for any published number. The withholding is the credibility story.

See [Benchmarks](concepts/benchmarks.md) for the full methodology and caveats.

### Is it production-ready? Who uses it?

The tooling is **real, tested, and CI-gated** — the scanners, the gate, the MCP server, and the signed release pipeline all work today.

That said, in the interest of honesty: **there are no production users yet.** SecureVibe is new. We'd rather tell you that than invent adoption numbers. Try it, and tell us where it breaks.

### How is it licensed? Can I use it commercially?

**MIT.** Yes — you can use it commercially, modify it, and redistribute it. There is no paywall on any security fix.

!!! note "Open-core boundary"
    Everything that finds or prevents a vulnerability is free and open. The only things that would ever be paid are **scale and trust infrastructure** — a central signing pipeline, a private registry, fleet policy, SLAs. A security fix is never paywalled.
