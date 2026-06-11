# Evaluation (`eval/`)

Holds the evaluation harness and — critically — the **decision-gate spike** that must run before
any Stage 2+ work. See `IMPLEMENTATION_STRATEGY.md §6` and `debate/05_final_architecture.md §5, §A.2`.

## `spike/` — the decision gate (SCAFFOLDED, runnable)

The offline gate run on a historical corpus with known outcomes. It emits a **falsifiable verdict**:

- **Test A — miss-rate τ-sweep** (C3): `miss = max ranker score over candidates < τ`. Plots
  miss-rate vs τ. A high miss-rate at sane τ **refutes** the tiered KG-first design (a reasoner-first
  design was right).
- **Test B — re-ranker accuracy** (B5): top-1/3/5 + MRR of the *correct* technique — not just that
  an ID resolves to *some* object.
- **Verdict**: high miss-rate at sane τ **OR** low top-1 ⇒ **VETO** the dispatcher-as-specified.

Run it:

```bash
python eval/spike/run_spike.py --seed                       # seed index, offline, deterministic
python eval/spike/run_spike.py                              # full ATT&CK if present in data/attack
python eval/spike/run_spike.py --corpus eval/corpora/incidents.jsonl --out eval/spike/out/r.json
```

Pieces (each is the seam where the real component plugs in):
- `corpus.py` — `CorpusItem` schema + JSONL loader. Empty `ground_truth` = a genuine no-mapping case
  (drives miss-rate; never silently dropped).
- `ranker.py` — the `Ranker` protocol + `LexicalRanker` **baseline**. ⚠ The baseline is a stand-in;
  the real gate uses the **frozen non-LLM re-ranker over the KG frontier** (Stage 2, B4).
- `metrics.py` — `tau_sweep`, `ranker_accuracy`, `gate_verdict` (pure, tested).
- `sample_corpus.jsonl` — **synthetic** demo corpus (committed). Real corpora go in `eval/corpora/` (gitignored).

> **This is the measurement framework, not a decision.** Baseline-ranker numbers on a synthetic
> corpus are not decision-grade — and indeed the baseline already flips PROCEED→VETO between the seed
> and full index, which is exactly why the real frozen re-ranker + a historical corpus + calibrated
> thresholds (C4) are required before the verdict means anything.

## `harness/` — not yet built

Layer 1 (LLM-as-judge, regression), Layer 2 (expert eval = the Stage-1 value gate), Layer 3 (holdout
benchmarks); test B as a seeded-decoy lab benchmark; the pre-registered **kill-criterion** (C6).

## `corpora/` — pointers to historical incidents/CTI with known outcomes. **Never committed** (`.gitignore`).
