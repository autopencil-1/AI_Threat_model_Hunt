# Evaluation (`eval/`)

Not yet built. This directory holds the evaluation harness and — critically — the **decision
gate spike** that must run before any Stage 2+ work. See `IMPLEMENTATION_STRATEGY.md §6` and
`debate/05_final_architecture.md §5, §A.2`.

- `spike/` — the offline **decision gate** run on a historical corpus:
  - **miss-rate τ-sweep** (test A): plot miss-rate vs τ; a high miss-rate at sane τ **refutes**
    the tiered KG-first design (falsifiable — it can return "don't build the dispatcher").
  - **re-ranker accuracy** (B5): does an ID resolve to the *correct* technique, not just *some* object.
- `harness/` — Layer 1 (LLM-as-judge, regression), Layer 2 (expert eval — the Stage-1 value
  gate), Layer 3 (holdout benchmarks); test B (on-graph false-approval, seeded-decoy lab);
  the pre-registered **kill-criterion** (C6).
- `corpora/` — pointers to historical incidents/CTI with known outcomes. **Never committed** (see `.gitignore`).

Stage 1 ships with no dependency on this directory; it exists to enforce *measure-before-you-build*.
