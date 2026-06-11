# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

This repo has **two layers**:

1. **A Claude-Code-agent-orchestrated structured debate** (the origin) that produced an
   engineering decision record answering: *what is the most feasible architecture for AI agents
   in threat modeling and threat hunting?* Lives in `.claude/agents/` + `debate/`.
2. **A Python implementation** of the adopted architecture's Stage 1. `IMPLEMENTATION_STRATEGY.md`
   is the build plan; `src/threat_agents/` is the code. See **Implementation** below.

The "debate program" is a set of four custom subagents (in `.claude/agents/`) plus an ordered
file pipeline (in `debate/`). The main Claude session is the **driver**: it invokes the
subagents in the sequence the orchestrator spec defines, and the artifacts accumulate in
`debate/`.

The substantive input is the reference doc `Architectures for AI Agents in Threat Modeling
and Threat Hunting.md` — a cited briefing on five framework-anchored agent designs (D1 STRIDE/PASTA,
D2 ATT&CK attack-chains, D3 attack-trees, D4 Diamond scenarios, D5 hunting loop), topology
guidance, and benchmark caveats. Everything in `debate/` extends or argues over this doc.

## The agents (`.claude/agents/`)

Four `opus`-model subagents, each a self-contained spec. The driver invokes them; they never
invoke each other.

- **`researcher`** — neutral. Two modes set by the invoking message: **PREP** (read the
  reference doc + web-research, write `01_background_research.md` and `02_criteria.md`) and
  **SYNTHESIZE** (read the full debate, write `05_final_architecture.md`). Never argues.
- **`orchestrator`** — neutral judge/sequencer. Defines the protocol (below), scores each round
  against the rubric in `02_criteria.md`, and records winners. Does not itself argue. The
  actual round-by-round driving is done by the main session, not by this agent — its file is
  the authoritative protocol + judging spec.
- **`debater-1`** — defends **Position A** (narrow, per-task deterministic pipelines, human-gated,
  incrementally deployed). Speaks **first** each round.
- **`debater-2`** — defends **Position B** (one unified supervisor/hierarchical multi-agent platform).
  Speaks **second**, must rebut D1's current-round argument before advancing its own.

## The debate protocol (how a run flows)

The driver executes the `orchestrator` spec's protocol:

1. **PREP** — invoke `researcher` (PREP) → produces `01_background_research.md` + `02_criteria.md`.
2. **Init logs** — create `03_debate_log.md` (full transcript) and `04_round_results.md` (scorecard table).
3. **Rounds (max 20)** — per round N: invoke `debater-1` with N + full `03_debate_log.md`, append
   its output; invoke `debater-2` with the now-updated log, append; then **judge** the round
   against the weighted rubric, append a judge block, add a `04_round_results.md` row with the
   running score. **Early-stop** on convergence, concession, or a decided-and-stale score.
4. **SYNTHESIZE** — invoke `researcher` (SYNTHESIZE) → `05_final_architecture.md`.

Each debater always receives the **full current transcript** as input, not a summary.

## `debate/` file pipeline (numbered = strict order)

| File | Author | Role |
|------|--------|------|
| `01_background_research.md` | researcher (PREP) | Neutral cited evidence brief, shared by both debaters |
| `02_criteria.md` | researcher (PREP) | **Rulebook**: the Motion, Position A/B theses, and the weighted judging rubric (Feasibility 25 · Reliability/safety 25 · Evidence 20 · Cost 12 · Extensibility 10 · Auditability 8) |
| `03_debate_log.md` | driver (appends) | Full round-by-round transcript + judge rulings |
| `04_round_results.md` | driver (appends) | Scorecard: Round · Winner · Margin · Reason · Running score |
| `05_final_architecture.md` | researcher (SYNTHESIZE) | The decision record — the synthesized architecture |
| `06_red_team_review.md` | independent reviewers | Adversarial post-hoc review (operator / impl-engineer / evidence-skeptic lenses); findings C1–C6, B1–B8 |
| `00_CONCLUSION.md` | — | Top-line verdict (the converged architecture) |

`05` is revised in response to `06` (see its Rev-history section — currently Revision 3).
`debate.zip` is a snapshot bundle, not a working input.

## Implementation (`src/threat_agents/`, Stage 1)

A Python/LangGraph implementation of the adopted architecture. Per the decision record's
load-bearing rule (`debate/05 §A`), only **Stage 1** is built: the proven core, **D1
(STRIDE/PASTA)** and **D3 (recursive AND/OR attack-trees)** — two independent
framework-as-state-machine graphs, each with its critic, on a lightweight versioned ATT&CK
reference index. **No dispatcher, substrate, cross-task coupling, or D2/D4/D5** — those are
Stage 2+ and gated behind an offline decision spike (`eval/`, not yet built). Stage 2+ modules
exist only as `NotImplementedError` stubs to mark intent.

**Commands** (run from the project root):
- `python -m pytest -q` — full suite (53 tests; pure-logic critics + tree-value propagation + STIX-loader + checkpointer + injection-boundary + spike + offline graph smoke tests). `pythonpath=["src","."]` is set in `pyproject.toml`.
- `python -m pytest tests/test_attack_tree_critic.py -q` — a single test file.
- `ruff check src tests eval examples scripts` — lint (F + I rules; config in `pyproject.toml`). CI (`.github/workflows/ci.yml`) runs ruff + the offline suite.
- `python scripts/replay_trace.py <trace.jsonl>` — print a persisted audit trace's deterministic replay signature.
- `python examples/run_d1.py` / `python examples/run_d3.py` — run each graph end-to-end **offline** (no API key, seed index, in-memory checkpointer).
- `python scripts/fetch_attack.py [VERSION]` — download a pinned ATT&CK STIX bundle into `data/attack/` (gitignored, ~50MB). `ReferenceIndex.load_default()` then uses the newest bundle there, falling back to the 45-technique seed offline.
- `python examples/run_live.py` — run D1+D3 against the real Anthropic API (key from `.env`), full ATT&CK index, and a **durable SQLite checkpointer** (`.threat_agents/`, gitignored).
- `python eval/spike/run_spike.py --seed` — run the **decision-gate spike** (miss-rate τ-sweep + re-ranker accuracy → falsifiable PROCEED/VETO). `--seed` forces the offline seed index; omit it to use full ATT&CK. The `LexicalRanker` is a placeholder; the real gate needs the Stage-2 frozen re-ranker + a historical corpus.

**Key design invariants** (don't break these — they encode the architecture):
- **Framework is the control flow; the LLM only fills bounded nodes.** Graphs depend on the
  `LLMClient` Protocol (`common/llm.py`), never a concrete SDK, and never let the model decide
  routing. `StubLLM` + `common/testing.py` is what makes everything testable without an API key.
- **Deterministic critics gate; semantic critics run shadow-mode.** D1 coverage and D3
  well-formedness are pure functions (no LLM) and gate. D3's semantic refinement critic has
  `SEMANTIC_CRITIC_HAS_GATING_AUTHORITY = False` until its false-confirmation rate clears (§2.4/C5).
- **Technique-ID resolution invariant:** every ATT&CK ID a node emits must resolve in the
  pinned `ReferenceIndex` (`enforce_resolves`), or hard-fail.
- **Human is the disposer:** `interrupt()` fires before publish (the side-effecting step);
  resume with `Command(resume={"approved": ...})`. No approval → no side effect.
- **Replayable audit:** trace records carry `ref_index_version`; `AuditTrace.replay_signature`
  excludes wall-clock `ts`. No `Date.now`/randomness in logic (stub ticket ids are a counter).
- **Grounding index:** `ReferenceIndex` is versioned + content-addressed (`from_stix` derives the
  version from the bundle's `x-mitre-collection`; sub-techniques resolve via their base). For a
  small (seed) index, `grounding_hint()` inlines the vocabulary into worker prompts; for full
  ATT&CK it switches to a short instruction (the invariant does the enforcing). This is Stage-1
  retrieval-lite — Stage 2 replaces it with KG-frontier top-k retrieval.
- **Checkpointer:** `common/checkpointer.py` — `make_checkpointer("sqlite", path)` for durable,
  resumable runs (interrupts survive restarts); `"memory"` for tests. Temporal/Restate is the
  Stage-4 durable-execution dependency, not this.
- **D3 recursion + values:** the attack-tree graph uses **true per-node `Send` recursion** via a
  `frontier` router loop (each depth level is a superstep barrier — no in-worker recursion).
  `values.py` propagates leaf cost deterministically (OR=min, AND/SAND=sum).
- **D1 fidelity:** STRIDE applicability is trust-boundary-aware (a crossing data-flow adds `S`); an
  explicit, justified **N/A determination** (`Threat.applicable=False`) counts as *considered* — a
  coverage gap means a category was **not addressed**, not that it was deemed N/A. Threats carry `severity`.
- **Injection boundary is wired in:** D1 `cti_context` and D3 `goal`/`context` pass through
  `IngestionBoundary` in the ingest node (control-char strip, deterministic IP/email pseudonymization,
  size bound) before reaching any LLM node. Honest limit: it's a hallucination/payload guard, not an
  on-graph-misdirection defense.
- **ConfidenceRecord** is populated on both pipelines' outputs and carried into the gate + audit trace.

## Conventions to preserve when editing artifacts

- **Citation discipline.** Every factual claim cites a source inline, e.g. `[source: title/url]`
  or an arXiv ID. Do not assert without a citation.
- **Evidence flags** (used in `05`/`06`): `[PRIMARY]` = peer-reviewed/vendor-authoritative/official;
  `[SELF-REPORTED]` = single-paper result on a small/custom set (a claim, not a validated fact);
  `[WEAK/CONTESTED]` = blog-tier or disputed. Preserve and apply these honestly.
- **Neutrality boundary.** `researcher` and `orchestrator` never argue a side; only the two
  debaters do. Keep that separation when modifying agent specs.
- **Debater output format** is fixed (Rebuttal → Affirmative/Negative case → Strongest point).
  Their final message *is* the round's speech — nothing else.
- **File numbering is the execution order.** Don't renumber; downstream files read upstream ones by path.

## Permissions

`.claude/settings.local.json` allows `WebSearch` and `WebFetch` only for `arxiv.org`,
`www.alphaxiv.org`, and `simbian.ai`. Research/citation work depends on these; widen the
allowlist there if a run needs another source domain.
