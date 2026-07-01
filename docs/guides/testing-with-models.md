# Test with a model

Run SecureVibe's prevention-lift eval yourself to see how its security skills change what a model actually writes.

## What you'll measure

The eval measures **prevention-lift**: how much a model's insecure-output rate drops when SecureVibe's skills are in its context. Every fixture is run across **three tiers**, so you can see the trend rather than a single point:

| Tier | What the model sees |
| --- | --- |
| `no-instructions` | The bare model — no security guidance. |
| `minimal-skill` | The skills document supplied as a system prompt. |
| `full-mcp` | The skills document **plus** the scanner exposed as a callable tool. |

Scoring is ground-truth-aware: on a vulnerable fixture, flagging the issue is success; on a clean fixture, flagging is a **false positive**; on a generation fixture, writing the bad idiom is insecure. A False-Positive column is reported alongside lift so a paranoid model can't fake prevention by flagging everything.

## Pick how you run it

Three ways to drive the eval, from free-and-keyless to API-metered. The flags are identical across providers — only `--provider` (and where the credentials come from) changes.

=== "Keyless / local (Ollama)"

    Free, no API key, runs entirely on your machine against a local Ollama model.

    ```bash
    python3 evals/benchmarks/llm-eval.py \
      --provider ollama \
      --model llama3.1:8b \
      --tier all \
      --run \
      --out-dir evals/baselines/leaderboard/llama3.1-8b
    ```

=== "Claude subscription (no billing)"

    Runs on your **Claude Code subscription** by shelling out to the local `claude` CLI. `ANTHROPIC_API_KEY` is stripped from the environment first, so there is **no metered API billing** — the run uses your existing subscription, not pay-as-you-go API credits.

    ```bash
    python3 evals/benchmarks/llm-eval.py \
      --provider claude-cli \
      --model sonnet \
      --tier all \
      --run \
      --out-dir evals/baselines/leaderboard/claude-sonnet
    ```

    Pick the model with `--model opus`, `--model sonnet`, or `--model haiku`.

=== "API key"

    Uses a metered provider API. Put the key in your environment (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) and select the provider:

    ```bash
    python3 evals/benchmarks/llm-eval.py \
      --provider anthropic \
      --model sonnet \
      --tier all \
      --run \
      --out-dir evals/baselines/leaderboard/anthropic-sonnet
    ```

    Use `--provider openai` (with `OPENAI_API_KEY` set) to run against OpenAI models the same way.

## Try it without spending anything first

Before you point the eval at any model, check the pipeline for free:

- **Dry run** — omit `--run`. The harness lists the fixtures it would execute and exits without calling any model:

  ```bash
  python3 evals/benchmarks/llm-eval.py --provider ollama --model llama3.1:8b --tier all
  ```

- **Self-check** — `--self-check` runs the full scoring pipeline through a deterministic keyless mock provider. It calls no real model, costs nothing, and is CI-safe:

  ```bash
  python3 evals/benchmarks/llm-eval.py --self-check
  ```

## Build the cross-model leaderboard

Once you have one or more completed runs in `evals/baselines/leaderboard/`, rank them:

```bash
python3 evals/benchmarks/llm-eval.py --leaderboard
```

The leaderboard ranks models by `full-mcp` lift, and only **real, complete** runs are included — partial or mock runs are excluded.

## Get a trustworthy score

By default the harness scores model output with a **regex classifier**. It is fast, but **brittle**: it can mislabel a secure answer that explains the risk it avoided. When skills make a model write safe code *and* name the threat (for example, "strip CR/LF to prevent log injection (CWE-117)"), the regex can match that warning text and score the secure output as a vulnerability.

For a trustworthy result, add `--judge`, which swaps the regex for an LLM-judge classifier:

```bash
python3 evals/benchmarks/llm-eval.py \
  --provider claude-cli \
  --model sonnet \
  --tier all \
  --run \
  --judge \
  --out-dir evals/baselines/leaderboard/claude-sonnet
```

`--judge` re-runs the model as part of scoring, so it is slower and (on metered providers) costs more — but it is the basis for any score worth trusting. See [Benchmarks](../concepts/benchmarks.md) for the full explanation of why the regex aggregate is an artifact rather than a signal.

!!! warning "Your local number is not a published result"
    Any single prevention-lift figure you get from a local run is **exploratory, not an official result**. The project deliberately withholds a headline prevention-lift number until judge-based scoring is the basis for it, precisely because the default regex classifier can misscore secure-with-explanation output. Treat your run as a way to explore the methodology and the three-tier trend — not as a number to quote.
