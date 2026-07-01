# Prevention-lift leaderboard

Cross-model ranking of SecureVibe's **prevention-lift** — the absolute drop in a
model's insecure-output rate when the skills + `scan_input` tool are placed in
its context. `LEADERBOARD.md` here is generated; do not hand-edit it.

## Layout

One subdirectory per model, each containing the three tier baselines produced by
`llm-eval.py`:

```
evals/baselines/leaderboard/
  claude-haiku-4-5/
    no-instructions.json
    minimal-skill.json
    full-mcp.json
  llama3.1-8b/
    no-instructions.json
    minimal-skill.json
    full-mcp.json
  LEADERBOARD.md      <- generated
```

## Populate a model

Run all three tiers for a model into its own dir, then rebuild the board:

```bash
# Keyed (Anthropic):
ANTHROPIC_API_KEY=sk-ant-… python3 evals/benchmarks/llm-eval.py \
    --tier all --model claude-haiku-4-5 --run \
    --out-dir evals/baselines/leaderboard/claude-haiku-4-5

# Keyless (local Ollama):
python3 evals/benchmarks/llm-eval.py --provider ollama --model llama3.1:8b \
    --tier all --run \
    --out-dir evals/baselines/leaderboard/llama3.1-8b

# Rebuild the ranked board:
python3 evals/benchmarks/llm-eval.py --leaderboard
```

## Honesty rules (enforced by the generator)

- **Only real, complete runs are ranked.** A run whose `agent` is `mock*` or the
  committed `TEMPLATE`, or that is missing any tier, is listed under "Not
  ranked" and never enters the table.
- **Numbers are never faked.** With no real runs present, the board says so. The
  committed root baselines (`evals/baselines/*.json`) are TEMPLATES and are not a
  leaderboard entry.
- Ranking key is the **full-mcp prevention-lift** (descending). The board also
  shows the per-model false-positive count so a high lift bought with paranoia is
  visible, not hidden.

The generator wiring is covered keylessly by `llm-eval.py --self-check`
(`_check_leaderboard`), which CI runs.
