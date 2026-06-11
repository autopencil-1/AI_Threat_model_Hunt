# Implementation Strategy

**Project:** AI Agents for Threat Modeling & Threat Hunting
**Source of truth:** `debate/05_final_architecture.md` (Rev 3, ADOPTED) · `debate/00_CONCLUSION.md` · red-team findings in `debate/06_red_team_review.md`.
**This document:** translates the adopted decision record into a concrete, sequenced engineering plan. It does **not** re-decide the architecture — where it deviates or sharpens, it says so explicitly.

---

## 0. The one rule that shapes everything

The decision record's load-bearing recommendation (§A) is **prove the core before building the synthesis**:

- **Proven core (build NOW):** D1 (STRIDE/PASTA threat modeling) + D3 (recursive AND/OR attack-trees) — the only two tasks with real-deployment prior art (ASTRIDE/STRIDE-GPT, DefenseWeaver). Each a self-contained deterministic LangGraph graph with its own critic. **No dispatcher. No Tier-2 reasoner. No KG substrate beyond a lightweight reference index. No cross-task coupling. No promotion loop.**
- **Speculative synthesis (EARN it, don't build it yet):** the three-store substrate, dispatcher, tiering, Tier-2 reasoner, promotion loop, D4, D5. These are gated behind a measurement spike (§Decision Gate) whose result *can return "don't build it."*

Every stage below respects this. We do not skip ahead. The dispatcher diagram in `05_final_architecture.md §2.0` is the **target** state, not the **next** state.

---

## 1. Guiding principles (carried from the record)

| Principle | Implication for the build |
|---|---|
| **Framework is the control flow; LLM only fills bounded nodes.** | Graph topology is hand-authored. The LLM never decides routing. Classification/drafting only, inside fixed nodes. |
| **Externally-grounded critic per pipeline — never self-reflection alone.** | Every graph ends in a critic node. Structural critics gate from day one; semantic critics run shadow-mode until their false-confirmation rate clears (§Cross-cutting → Critics). |
| **Human is always the disposer.** | `interrupt()` before any side-effecting step / publish. No autonomous disposer, ever. |
| **Gate only side-effecting steps.** | Read-only queries against already-authorized telemetry do **not** interrupt (relevant from D5/Stage 4). |
| **Deterministic, replayable, version-pinned.** | `kg_version` (or `ref_index_version` in Stage 1) in the trace schema from day one to avoid retrofit churn. |
| **Instrument-first / falsifiable.** | The decision gate has a pre-stated outcome that *kills* the dispatcher design. We measure before we build. |
| **Integrate, don't replace.** | Stage 0: feed existing approval queue + SIEM/EDR APIs under existing RBAC. A bespoke UI gets routed around in a week. |

---

## 2. Technology decisions

These are dictated or strongly implied by the record; pinned here so the build is unambiguous.

| Concern | Choice | Rationale / source |
|---|---|---|
| Language | **Python 3.11+** | LangGraph is the named orchestration framework. |
| Orchestration | **LangGraph** (`StateGraph`, `Send`, `Command`, `interrupt()`, subgraphs, checkpointer) | Named throughout `05 §2.1`. All five designs map to these primitives. |
| LLM | **Claude (latest available)** for bounded classification/drafting and the semantic critic | Default to the most capable Claude model; the critic uses an *independence lever* — a different model or a different grounding view (§Cross-cutting → Critics). |
| ATT&CK data (Stage 1) | **`mitreattack-python`** / `attackcti` loading STIX 2.1 from `attack-stix-data`; stored as a **lightweight, versioned local reference index** (SQLite + JSON, or in-memory map keyed by technique ID) | Stage 1 needs only ID resolution + lookups, *not* the Neo4j KG (`05 §A.1`). |
| KG substrate (Stage 2+) | **Neo4j-style graph**, CVE→CWE→CAPEC→ATT&CK, content-addressed + versioned, **frozen non-LLM re-ranker** (cross-encoder / learned-to-rank) | `05 §2.2`, B4. Built only if the decision gate passes. |
| Durable execution (Stage 4) | **Temporal or Restate** | `05 §2.5`. Checkpointers ≠ durable execution for day-long hunts. Named dependency, validated before reliance. |
| Persistence / checkpointer | LangGraph checkpointer (SQLite for dev, Postgres for prod) | Standard LangGraph persistence. |
| Eval | LLM-as-judge (regression) + expert eval (the real bar) + holdout benchmarks | `05 §5`, three layers. |
| Integration targets | XSOAR / ServiceNow (approval queue); Splunk / Sentinel / CrowdStrike (telemetry APIs) | `05 §4 Stage 0`, B7. Adapter interfaces, concrete connector per customer. |

---

## 3. Proposed repository layout

```
src/threat_agents/
  common/
    schema.py            # TraceNode, ConfidenceRecord, Finding, KGRef, DFD, AttackTree (typed)
    audit.py             # append-only trace writer; deterministic replay; version pinning
    llm.py               # LLM client behind a Protocol; Anthropic + offline stub
    injection_boundary.py# single hardened ingestion boundary (CTI/web/logs)
    grounding/
      reference_index.py # Stage 1: lightweight ATT&CK/CAPEC index (ID resolution + lookup)
      kg.py              # Stage 2+: Neo4j base KG, frozen re-ranker, hierarchical retrieval
      artifact_store.py  # Stage 2+: append-only, sign-off-gated, provenance-tracked
      overlay.py         # Stage 2+: promoted-edges overlay + offline curation gate
    integrations/        # Stage 0: SIEM/EDR/SOAR/ticketing adapters (base + stubs)
  graphs/
    d1_stride/           # STRIDE/PASTA over a DFD — Send fan-out per element
    d3_attack_tree/      # recursive AND/OR tree — Send fan-out per frontier node
    d2_attack_chain/     # Stage 3
    d4_diamond/          # Stage 3
    d5_hunting/          # Stage 4 (copilot only)
  dispatcher/            # Stage 3: parent StateGraph; subgraph routing; gate node
eval/
  spike/                 # the §Decision Gate offline spike: τ-sweep + re-ranker accuracy
  harness/               # Layer 1/2/3 eval; test A (miss-rate), test B (false-approval)
  corpora/               # historical incidents/CTI with known outcomes (gitignored / pointer)
examples/                # runnable end-to-end demos (offline stub LLM)
tests/                   # pure-logic tests: critics, matrix, index, schema/audit
```

> **Stage 1 status:** the modules above without a `# Stage N` marker are **scaffolded** in this repo (`src/threat_agents/common/*`, `graphs/d1_stride`, `graphs/d3_attack_tree`, `examples/`, `tests/`). LLM calls sit behind `common/llm.py` so graph topology and the **deterministic critics are fully testable offline** without an API key.

**Module boundary discipline (B1):** "independent" means **independently-authored, separately-testable modules** — not separate runtimes. Each graph in `graphs/` is importable and testable in isolation; the Stage-3 dispatcher mounts them as subgraphs.

---

## 4. Staged work breakdown

### Stage 0 — Integration substrate *(requirement, not a nicety — B7)*

**Goal:** the system delivers into tools the SOC already uses; nothing bespoke they must watch separately.

- `integrations/`: adapter interface + first concrete connectors — approval queue (XSOAR/ServiceNow), telemetry read (Splunk/Sentinel/CrowdStrike) under **existing RBAC**, output emitters in existing formats.
- This is thin in Stage 1 (gates publish threat models/trees into the ticket queue) and deepens at Stage 4 (telemetry queries).

**Definition of done:** a D1/D3 artifact can be pushed into the real approval queue; a stubbed telemetry read works against the adapter interface.

---

### Stage 1 — D1 + D3 MVP  *(the proven core — SHIPPABLE, DECISION-GATED)*

This is what we build first and ship. Everything here stands alone.

**Shared Stage-1 plumbing (minimal):**
- `common/schema.py` — `TraceNode`, `ConfidenceRecord` (typed, §Cross-cutting), `Finding`. Carry `ref_index_version` from day one (the Stage-1 analogue of `kg_version`) to avoid a retrofit later (doc 06 §C).
- `common/audit.py` — append-only trace; every node decision + every gate approve/edit/reject is a replayable trace node. Replay loads the **pinned** index version.
- `common/grounding/reference_index.py` — versioned ATT&CK/CAPEC lookup. Enforces the **technique-ID-resolution invariant**: every ATT&CK ID a graph emits MUST resolve to an object in the pinned index, or hard-fail. *(Resolution ≠ correctness — accuracy is measured later, B5.)*
- `common/injection_boundary.py` — single hardened entry for adversary-controlled input (least-privilege tooling, I/O filtering, deterministic pseudonymization, adversarial test set). Honest limit: stops pattern-matchable payloads, not a plausible on-graph decoy.

**D1 — STRIDE/PASTA** (`graphs/d1_stride/`)
- `StateGraph`; ingest a DFD (elements, data flows, trust boundaries).
- **`Send` fan-out per DFD element**; each worker node = bounded LLM classification of applicable STRIDE categories (+ ASTRIDE "A" AI-agent category) with a fixed reducer collecting results.
- **Coverage critic — DETERMINISTIC structural:** verifies every DFD element received every applicable STRIDE category. No LLM judgment → **gates from day one**.
- `interrupt()` before publishing the threat model.

**D3 — Recursive AND/OR attack-tree** (`graphs/d3_attack_tree/`)
- `StateGraph` + **recursive `Send`** fan-out per frontier node; **depth/loop guard** + reducer.
- Bounded LLM node refines each node into AND/OR children; leaves are atomic.
- **Critic, split (this resolves a spec inconsistency — see note):**
  - **Deterministic structural sub-critic (gates day one):** tree well-formedness (valid AND/OR/SAND node types, leaf atomicity, acyclic, depth bound respected, every emitted technique ID resolves in the pinned index).
  - **Semantic refinement-validity critic (shadow mode):** judges whether a refinement is *valid/complete*. Runs without gating authority until its false-confirmation rate clears the §Cross-cutting release gate.
- `interrupt()` before publishing the tree.

> **Resolved (follows `05 §2.4`):** `05 §A.1` loosely calls both D1 and D3 critics "deterministic structural," but the detailed `05 §2.1`/`§2.4` classify D3's refinement-validity critic as **semantic**. **Decision: follow §2.4.** D3 therefore ships with *two* critics — a deterministic *well-formedness* check that **gates from day one**, plus a *semantic* refinement-validity check that runs **shadow-mode (no gating authority) until its false-confirmation rate clears the §Cross-cutting release gate**. D1 keeps its single deterministic coverage critic.

**Stage-1 Definition of Done:**
1. D1 and D3 each runnable end-to-end on real inputs, producing audit-traced, human-gated artifacts pushed via Stage-0 integration.
2. Deterministic structural critics gating; semantic D3 critic instrumented in shadow mode.
3. Full deterministic replay works against a pinned `ref_index_version`.
4. **MVP value gate (Layer-2 expert eval):** D1+D3 demonstrate real, expert-rated value vs manual baselines. *If not, the synthesis is moot — stop here.*

---

### ▣ DECISION GATE — between MVP and substrate  *(§A.2 — the discipline Rev 2 lacked)*

**Do not build Stage 2+ until both pass.** Lives in `eval/spike/`, run on a **historical corpus (NOT in production)**.

1. **MVP value gate** (above) passes.
2. **Offline spike** measures, on incidents/CTI with known outcomes:
   - **Miss-rate τ-sweep (C3):** how often does KG-frontier retrieval fail to score *any* candidate above τ, across a range of τ? (Determines whether a tiered, fast-path-dominant shape is even right.)
   - **Re-ranker accuracy (B5):** not "does an ID resolve" but "does it resolve to the *correct* technique," scored against ground truth.

**Falsifiable outcome — stated up front:**
> If miss-rate at a sane τ is **high**, the tiered KG-first design is **wrong** and a reasoner-first (Position-B-like) design was right → **veto the dispatcher as specified, redesign.**
> If re-ranker accuracy is **low**, mis-grounding dominates and the off-graph detector buys almost nothing → same veto.

Only if the MVP earns its keep **and** the spike supports a tiered shape do we proceed.

---

### Stage 2 — Three-store substrate  *(only if the gate passes)*

- **Store (i) base KG:** Neo4j-style CVE→CWE→CAPEC→ATT&CK, **content-addressed + versioned**, **no runtime agent write path**; retriever + **frozen non-LLM re-ranker** + hierarchical retrieval. Version-pinned technique-ID invariant; re-ranker **accuracy** harness.
- **Store (ii) artifact store:** append-only, **sign-off-gated**, provenance-tracked; objects carry provenance + typed confidence + `run_id` + `kg_version`; reused as **confidence-weighted hypotheses, never grounding**; deprecation-migration path for ATT&CK releases.
- **Store (iii) promoted-edges overlay:** versioned, human-curated, read as grounding but tagged `provenance=promoted` and **confidence-capped**; written **only via a separate offline curation gate** (multi-sign-off / quarantine) — never the runtime `interrupt()`.
- Stand up the durable-execution layer (Temporal/Restate). Finalize the single audit/trace schema (replay @ pinned `kg_version`; typed confidence record). **Retrofit D1/D3.**

---

### Stage 3 — D2 + D4 + the dispatcher

- **D2 attack-chain:** guided single agent on a deterministic ATT&CK task tree; **deterministic precondition-as-reachability critic** (each technique's preconditions reachable from the prior phase's postconditions in the pinned KG).
- **D4 Diamond scenarios:** supervisor with a bounded pivot loop; **semantic pivot-consistency critic** with independence levers; emits typed `PivotRequest` on cross-task pivots.
- **Dispatcher = parent `StateGraph`; pipelines = subgraphs** via `Command(goto)`/`Send`. `PivotRequest` type, append-list reducer for concurrent pivots, `correlation_id` resume-map, multi-interrupt batching (single gate node after fan-out).
  - **Tier 1:** deterministic KG-frontier retrieval + frozen non-LLM re-ranker (edge-bound).
  - **Tier 2:** bounded open-generation reasoner, fires **only** on a genuine miss (`max re-ranker score over k-hop frontier < τ`); proposes one edge and stops.
  - **Gate node:** surface **evidence, not a verdict**; mandatory KG-citation as a **hallucination guard** (not an injection defense, B6); independent critic re-check before the human; **typed-confidence decision rule** (never silently deny; genuine miss always escalates); `interrupt()` only on **side-effecting** steps; queue-overflow / shift-change policy.
- **τ-sweep instrumentation on from day one in production;** default tier changes only via the floor-tuning owner's human gate (no auto-promotion). Promotion routed to the **offline** curation gate.

---

### Stage 4 — D5 hunting copilot  *(LAST — highest risk, lowest autonomy)*

- D5 cyclic graph (Sqrrl/TaHiTI/PEAK: hypothesis → query → evidence → refine), **copilot only — never autonomous** (Cyber Defense Benchmark: no frontier model passes open-ended hunting).
- On the durable-execution layer; **read-only telemetry queries do not interrupt**; side-effecting actions carry an idempotency key (side effects + trace appends strictly *after* the interrupt resolves).
- Evidence-surfacing critic presents logs/linkages without prescriptive labels.
- Validate durable execution for day-long hunts before reliance.

---

## 5. Cross-cutting components

**Typed confidence record (C4)** — replaces any scalar "confidence floor." Fields: `retrieval_relevance`, `attribution_class_ceiling` (e.g. fine-grained actor ≤ ~0.63), `reuse_chain_confidences`, `critic_verdict` ∈ {pass, fail, abstain}, `provenance` ∈ {base, promoted, artifact} (promoted is capped). **No threshold is set until confidence is calibrated against a held-out corpus (reliability diagram).**

**Decision rule (C4):** genuine KG-miss **escalates regardless of confidence**; default-deny applies **only** to high-volume, low-novelty, on-graph proposals; **nothing is silently denied** (denied-items ledger; deny-rate is itself monitored).

**Critics — independence levers + release gate (C5):**
- Deterministic structural critics (D1 coverage, D2 precondition) gate from day one.
- Semantic critics (D3, D4, D5) must carry ≥1 independence lever — **different model**, **different grounding view**, or **reduction to constraint-satisfaction** — and run **shadow-mode (no gating authority) until their false-confirmation rate clears a stated bound.**

**Audit/trace schema:** every node decision + gate disposition + *which artifact informed which decision*, carrying `run_id`, version pin, and the typed confidence record; deterministic replay loads the **pinned snapshot, not "current."**

**Day-2 RACI (must be assigned, not implied — doc 06 §C):** KG-ingestion owner · per-pipeline critic owners (hold the shadow-mode release gate) · floor-tuning owner (calibration, τ-sweep, default-tier human gate) · injection-rule owner · artifact-curation owner (runs the offline promotion gate).

---

## 6. Evaluation harness  (`eval/harness/`)

- **Layer 1 — LLM-as-judge:** regression only, not go/no-go (inherits the self-critique paradox).
- **Layer 2 — Expert eval:** the real bar; comparative + coverage vs manual baselines. **This is the Stage-1 value gate.**
- **Layer 3 — Holdout benchmarks:** Cyber Defense Benchmark (D5 ceiling), DefenderBench, ATT&CK-mapping + **re-ranker accuracy** (not just resolution), AURA-style attribution.
- **Test A — miss-rate τ-sweep:** offline first (decision gate), then production from Stage 3; sets the default tier; **falsifiable** (high miss-rate refutes the tiered design).
- **Test B — on-graph false-approval rate:** seeded-decoy lab benchmark (synthetic ground truth, explicit lower-bound proxy); plant real, cleanly-grounding decoy techniques and measure analyst false-approval; instruments analyst **dwell-time per gate** (the rubber-stamp tell).
- **Pre-registered kill-criterion (C6):** if evidence-first framing does **not** beat verdict-framing **and** on-graph false-approval exceeds threshold X% → **lower autonomy** (second reviewer / narrow what the copilot surfaces / pull a task to advisory-only). HITL is a hypothesis under test, not a proven safeguard.

---

## 7. Risks & ceilings carried into the build  (`05 §6`)

These are documented, not closed — keep them visible in the backlog:

1. **No autonomous hunting, ever** (under current evidence). D5 stays a copilot.
2. **On-graph misdirection injection is irreducible** — the off-graph detector does **not** defend against it (it's a hallucination guard). Mitigations (shadow-channel canaries, N parallel hypotheses, analyst rotation) are **costed, not free**; if unpaid, downgrade the claim to "bounded blast radius + post-hoc audit."
3. **Mis-grounding from ordinary error** (~60–70% re-ranker accuracy at ~600-technique cardinality) — measure accuracy, not just resolution.
4. **Automation bias survives at both tiers;** evidence-first is unfalsified.
5. **Promotion is an audited offline risk,** not a closed one.
6. **KG versioning is operational, not free** (ATT&CK ~2×/yr; unowned → replay silently breaks).
7. **No ground truth** for threat-model/attack-tree completeness — evaluate by coverage + comparison.
8. **Self-critique paradox** — semantic critics need independence levers + shadow-mode gating.
9. **Attribution ceiling ≤ ~63% top-1** — always a confidence-weighted hypothesis.
10. **The entire coupling synthesis is the least-evidenced part** — earn it via the decision gate; the Tier-2 reasoner has no end-to-end source.
11. **Durable execution for long hunts is a named dependency, not solved** — validate before reliance.
12. **Cost/latency is a first-class gate** — ~$18/run baseline; misdirection defenses multiply cost and gate load N×.

---

## 8. Sequencing summary

```
Stage 0  Integration substrate (thin) ─┐
Stage 1  D1 + D3 MVP ──────────────────┤── ship + measure
            │
            ▼
        ▣ DECISION GATE  (value gate + offline τ-sweep & re-ranker-accuracy spike)
            │  high miss-rate / low accuracy → VETO, redesign
            ▼  (only if it passes)
Stage 2  Three-store substrate + durable execution + retrofit D1/D3
Stage 3  D2 + D4 + dispatcher (Tier-1/Tier-2, gate node, τ-sweep in prod)
Stage 4  D5 hunting copilot (last; copilot only)
```

No always-on supervisor is ever built. The speculative synthesis is **earned, not assumed.**

---

*Derived from `debate/05_final_architecture.md` (Rev 3). The one record ambiguity — the D3-critic classification — is **resolved in favor of §2.4** (§4): a deterministic well-formedness critic that gates day one, plus a semantic refinement-validity critic in shadow mode.*
