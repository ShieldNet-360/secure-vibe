# secret-detection benchmark

Corpus: `skills/secret-detection/tests/corpus.json` (232 fixtures: 129 TP, 103 TN)

> **Honesty note.** The secure-vibe secret rule set is *tuned*
> against this corpus — perfect or near-perfect numbers here
> only show the rules cover their own test bed, not that they
> will generalize. The gitleaks column is the more interesting
> signal: it measures how a popular general-purpose ruleset
> scores on shapes that the secure-vibe claims to handle.
> Treat regressions in the gitleaks column as expected when
> we add a new pattern that gitleaks does not know about, and
> regressions in the secure-vibe column as a hard fail.

| engine | TP | FP | FN | TN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| secure-vibe secret-detection patterns | 129 | 0 | 0 | 103 | 100.0% | 100.0% | 100.0% |
| gitleaks (default ruleset, `gitleaks`) | 85 | 7 | 44 | 96 | 92.4% | 65.9% | 76.9% |
