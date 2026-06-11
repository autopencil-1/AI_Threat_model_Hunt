# 05 — Final Architecture (Engineering Decision Record)
## The Most Feasible Architecture for AI Agents in Threat Modeling and Threat Hunting

**Status:** ADOPTED — converged decision record (debate ran **6 rounds of 20**), **then revised twice under independent adversarial red-team review** (`06_red_team_review.md`). This is **Revision 3**: it honestly remediates two flat internal contradictions, an undefined control signal, an unbuildable confidence gate, an unspecified dispatcher, a throughput-collapsing gate, several over-reaching claims, and — most importantly — **re-frames the headline recommendation** so the proven core is shipped first and the speculative synthesis is *instrumented-first / earned*, not presented as equally settled.
**Author:** Neutral Background Researcher (SYNTHESIZE mode). Strictly neutral; this records the converged design and its remediated form, not an advocacy of either pure position.
**Inputs:** `01_background_research.md` (evidence + flags), `02_criteria.md` (motion + weighted rubric), `03_debate_log.md` (6-round transcript + judge rulings), `04_round_results.md` (scorecard), `06_red_team_review.md` (three-lens adversarial review; findings C1–C6, B1–B8).
**Evidence flags used inline:** `[PRIMARY]` = peer-reviewed / vendor-authoritative / official docs; `[SELF-REPORTED]` = single-paper result on a small/custom set (claim, not validated fact); `[WEAK/CONTESTED]` = blog-tier or disputed.

---

## 0. Revision history / Rev 3 changelog (post-red-team)

Rev 3 is a remediation of `06_red_team_review.md`. The **citations were all verified real and correctly attributed** (doc 06 §D) — the flaws were in *reasoning over* the evidence and in *under-specification*, not in the facts. The fixes below are grouped by how they touch the architecture.

**Headline change (B3).** The recommendation is re-framed. The only two **deployment-proven** tasks are D1 (ASTRIDE/STRIDE-GPT) and D3 (DefenseWeaver). The cross-task coupling machinery (dispatcher, tiering, promotion, D4, D5) is the **least-evidenced, most-extrapolated** part of the design; it exists chiefly to serve D4 pivoting and D5 hunting (D5 at the autonomy floor, D4 grounding-fragile). Rev 2 presented it as co-equal with the proven core; Rev 3 does not. **Stage 1 is now a shippable, decision-gated D1+D3 MVP with NO dispatcher, NO Tier-2 reasoner, NO cross-task coupling.** The substrate + dispatcher are built only after (a) the MVP demonstrates real value and (b) an offline spike on a historical corpus measures the miss-rate τ-sweep (C3) and the re-ranker accuracy (B5). See the new **§A. Recommended path**.

**Architecture-changing fixes (contradictions / blockers):**
- **C1 — promotion-loop poisoning.** The "immutable + un-poisonable KG that *also* grows new edges" was a flat contradiction. Replaced with **THREE stores**: (i) versioned, content-addressed, read-only **base KG**; (ii) append-only, sign-off-gated **artifact store**; (iii) a NEW versioned, human-curated **promoted-edges overlay** read as grounding but tagged `provenance=promoted` and confidence-capped, with promotion via a **separate offline curation gate** (multi-sign-off / quarantine), never the runtime `interrupt()`. We **stopped calling any composite "structurally un-poisonable"**; the honest claim is "**no runtime agent write path to the base KG; promotion is an explicit, audited, offline curation surface.**"
- **C2 — KG versioning.** Base KG is now **versioned + content-addressed**; `kg_version` is in the trace/artifact schema; every run is **pinned to a snapshot**; the technique-ID invariant resolves against the run's pinned version; replay loads the pinned snapshot (not "current"); a **deprecation-migration path** handles ATT&CK releases (~2×/yr).
- **C3 — tiering signal defined + made falsifiable.** "Miss" is now `max re-ranker score over the k-hop KG frontier < τ`; instrumentation is a **τ-sweep**, not a single number; the **falsifiable prediction is stated** (if miss-rate is high at sane τ, the tiered design is wrong and a reasoner-first design was right); the default-tier promotion rule is explicit and **human-gated** (no auto-promotion).
- **C4 — confidence calculus + never-silently-deny.** The scalar "confidence floor" is replaced with a **typed confidence record** + a decision rule. A **genuine KG-miss escalates regardless of confidence**; default-deny applies **only to high-volume, low-novelty, on-graph proposals**; **nothing is silently denied** (below-threshold items are logged + counted); confidence must be **calibrated (reliability diagram)** before any threshold is set.
- **B1 — dispatcher topology specified.** The dispatcher is a **parent `StateGraph`**; per-task pipelines are **subgraphs** invoked via `Command(goto)`/`Send`; "independent" is redefined as **independently-authored, separately-testable modules**. The `PivotRequest` type, an append-list reducer for concurrent pivots, and `Command(resume=...)` routing keyed by `correlation_id` are defined; multi-interrupt batching (one gate node after fan-out, resume-map keyed by interrupt ID) is specified.
- **B2 — gate only side-effecting steps.** Read-only queries against already-authorized telemetry **do NOT interrupt**; only externally-acting / side-effecting steps (containment, external enrichment, writes) interrupt. Disposition is **batched + checkpointed at decision boundaries**; a **queue-overflow / shift-change policy** is added. Fixes the throughput collapse.

**Claim fixes / added specification:**
- **C5** — critics **split** into deterministic structural (D1 coverage; D2 precondition = graph reachability) vs semantic (D3/D4); semantic critics require **independence levers**; per-critic false-confirmation-rate is a **per-pipeline release gate** (shadow-mode until cleared).
- **C6** — HITL efficacy is stated as **UNFALSIFIED, not validated**; a pre-registered **kill-criterion** is added (lower autonomy if test B fails); analyst **dwell-time per gate** is instrumented.
- **B4** — Tier-1 re-ranker is specified as a **non-LLM deterministic** cross-encoder / learned-to-rank with frozen weights; if an LLM re-ranker is ever used the determinism/cost claims are **downgraded** to "replayable given pinned model + cached I/O."
- **B5/B6** — **mis-grounding** ("grounds to SOME object" ≠ "grounds to the CORRECT object") is now a first-class failure mode; we measure re-ranker **accuracy**, not just resolution success; the off-graph detector is **reframed as a hallucination guard**, not an injection defense (a rational injector picks an on-graph decoy).

**Requirements added:**
- **B7** — SIEM/EDR/SOAR/ticketing integration is a **Stage-0 requirement** (gates into the existing approval queue; telemetry via existing APIs + RBAC; outputs consumed by existing tools).
- **B8** — on-graph-misdirection defenses are **costed honestly** (N-parallel multiplies cost + gate load; analyst rotation needs staffing; canaries via a **shadow channel**, never production telemetry) OR downgraded to "bounded blast radius + post-hoc audit."
- **Day-2 ops RACI** added; a **durable-execution dependency** (Temporal/Restate) is named for day-long hunts; the **`interrupt()`-idempotency-vs-audit-logging** tension is fixed (side effects + trace appends strictly AFTER the interrupt; idempotency key per external query).

**Rubric-mapping honesty adjustments:** Cost-12 softened (B4), Reliability-25 softened (C1/C4/C6), Auditability-8 softened (C2). The rubric language is now honest rather than triumphant where the red-team weakened a claim.

**What did NOT change (still valid):** the five designs' framework spines / topologies / LangGraph primitives; the per-task externally-grounded critic principle; the autonomy ceiling (no autonomous disposer); the attribution ceiling; the no-ground-truth caveat; the self-critique caveat; the PRIMARY vs SELF-REPORTED honesty discipline; the evaluation plan's shape (sharpened, not replaced).

---

## A. Recommended path: prove the core before building the synthesis (B3)

> **This is the load-bearing recommendation of Rev 3.** Read it before §1.

The motion asks for the *most feasible* architecture **today**. The honest answer separates a **proven core** from a **speculative synthesis**, and ships them on different evidentiary footings.

**The proven core (ship this first):** D1 (STRIDE/PASTA threat-modeling) and D3 (recursive AND/OR attack-trees) are the **only two tasks with real-deployment prior art** — ASTRIDE/STRIDE-GPT and DefenseWeaver (8,200+ trees, 11 pen-test-verified paths in automotive production) `[SELF-REPORTED, real deployment]`. Each is a self-contained deterministic LangGraph graph with a deterministic structural critic. **Neither needs the KG substrate, the dispatcher, Tier-2, cross-task coupling, or the promotion loop.**

**The speculative synthesis (earn this second):** the dispatcher, tiering, promoted-edges overlay, D4 (Diamond pivoting), and D5 (hunting copilot) are the **least-evidenced, most-extrapolated** components. They exist almost entirely to serve **D4 pivoting** and **D5 hunting** — and:
- **D5 is at the autonomy floor:** no frontier model passes open-ended hunting (Cyber Defense Benchmark, `[PRIMARY]`, ~0.46 coverage, ~$18/run).
- **D4 is grounding-fragile:** Diamond pivoting depends on correct re-ranking over ~600-technique cardinality, where re-ranker accuracy is plausibly ~60–70% (B5) — *mis-grounding to a plausible-but-wrong technique is a routine error, not just an adversarial one*.

Rev 2 labeled the proven ~30% the "backbone" and built the speculative ~70% as if it were co-settled. **Rev 3 corrects this.** The coupling machinery must be **instrumented-first / earned**, not asserted.

### A.1 The D1+D3-only MVP (Stage 1), evaluated explicitly

**What it is:** two independent graphs (D1, D3), each with a deterministic structural critic, a minimal audit/trace schema, a minimal injection ingestion boundary, and **Stage-0 SIEM/ticketing integration** (B7). **No dispatcher. No Tier-2 reasoner. No KG substrate beyond a lightweight CAPEC/ATT&CK reference index. No cross-task coupling. No promotion loop.**

**Why it is genuinely the most feasible thing to ship today:**
- It is the part with real-deployment evidence.
- It has no internal contradictions to resolve (the C1/C3/C4 contradictions all live in the coupling layer).
- It is fully replayable with a non-LLM critic and a pinned reference index.
- It delivers analyst value (threat models + attack trees) on day one.

**The honest argument *for* building more later (not now):** static silos cannot reuse each other's outputs, and cannot surface a pivot a hunt discovers. That gap is real — but it is a gap whose *value* and *frequency* are unmeasured. So we **measure before we build**.

### A.2 The decision gate between MVP and substrate

Before any of the substrate + dispatcher is built, two things must happen:

1. **MVP value gate.** D1+D3 must demonstrate real, expert-rated value in production against manual baselines (Layer-2 eval, §5). If it does not, the synthesis is moot.
2. **Offline spike on a historical corpus (NOT in production).** On a corpus of historical incidents/CTI with known outcomes, measure:
   - **The miss-rate τ-sweep (C3):** how often does a KG-frontier retrieval fail to score *any* candidate above τ, across a range of τ? This tells us whether a tiered (fast-path-dominant) design is even the right shape.
   - **The re-ranker accuracy (B5):** not "does an ID resolve" but "does it resolve to the *correct* technique," scored against the corpus's ground truth.

**Falsifiable outcome (C3):** if the miss-rate at sane τ is **high**, the tiered KG-first design is **wrong**, and a **reasoner-first (Position-B-like) design was right** — the design does **not** claim victory under all outcomes. If the re-ranker accuracy is low, mis-grounding (B5) dominates and the off-graph detector buys almost nothing. Either result **vetoes building the dispatcher as specified** and sends the design back to the drawing board. This is the discipline Rev 2 lacked.

Only if the MVP earns its keep **and** the spike supports a tiered shape do we proceed to Stage 2+ (§4).

---

## 1. Executive Summary

**The converged architecture (full target state).** Build **N independently-authored, framework-as-state-machine, per-task deterministic LangGraph graphs** (D1 STRIDE/PASTA, D2 ATT&CK attack-chains, D3 recursive AND/OR attack-trees, D4 Diamond+ATT&CK scenarios, D5 hypothesis-driven hunting *copilot*) — each with its own externally-grounded critic — over a **THREE-STORE shared substrate** (C1): (i) a **versioned, content-addressed, read-only base KG** (CVE→CWE→CAPEC→ATT&CK) that **no agent writes at runtime**; (ii) an **append-only, sign-off-gated, provenance-tracked artifact store** (D2/D3/D4 outputs, reused as confidence-weighted hypotheses, never as grounding); and (iii) a **versioned, human-curated promoted-edges overlay** read as grounding but tagged `provenance=promoted` and confidence-capped, written **only via a separate offline curation gate** (multi-sign-off / quarantine), never the runtime `interrupt()`. Plus **ONE hardened indirect-prompt-injection ingestion boundary** and **ONE audit/trace schema** with deterministic replay (pinned `kg_version`) and a **typed per-claim confidence record**. Cross-task coupling is served by a **single HITL-gated dispatcher implemented as a parent `StateGraph` with per-task subgraphs** (B1): **Tier 1** is a *deterministic KG-frontier retrieval + a frozen-weight non-LLM re-ranker* bounded to existing graph edges; **Tier 2** is a *bounded open-generation reasoner that fires only on a genuine KG-miss* (defined as `max re-ranker score over the k-hop frontier < τ`). The **default tier is set by an instrumented τ-sweep miss-rate** — and the design is **falsifiable** (a high miss-rate means a reasoner-first design was right). Side-effecting steps halt at `interrupt()`; **read-only queries against already-authorized telemetry do not** (B2). Validated novel pivots are promoted to overlay edges through the **offline curation gate only**. The build ships **the proven D1+D3 MVP first** (§A), and the substrate + dispatcher only after the MVP earns value and an offline spike supports a tiered shape.

**One-line verdict.** The motion was **refined, not won outright by either pure position** — *and* its synthesis layer is now correctly labeled as the speculative, instrument-first part rather than co-equal with the proven core. The **backbone is Debater 1's deterministic framework**; **Debater 2's grounded-reasoning-coordination core** is grafted into both dispatcher tiers, but **only after** an offline spike shows the tiered shape holds. Position A held **Feasibility (25)** and **Cost (12)** across all six rounds; Position B edged the contested conceptual exchanges by identifying what pure-A structurally could not do. Final rounds tally **D1 1 – 2 D2** with R4/R5/R6 convergence draws. **Rev 3 makes the synthesis earn its complexity before it is built.**

---

## 2. The Converged Architecture, Concretely

### 2.0 System shape (one diagram in words)

```
        ┌──────────────────────────────────────────────────────────────────────┐
        │  THREE-STORE SHARED SUBSTRATE  (C1, C2)                                │
        │                                                                        │
        │  (i) VERSIONED READ-ONLY BASE KG  ── no RUNTIME agent write path ──     │
        │      • ATT&CK / CVE→CWE→CAPEC→ATT&CK (Neo4j-style)                      │
        │      • CONTENT-ADDRESSED + VERSIONED; runs pin a kg_version snapshot    │
        │      • retriever + FROZEN non-LLM re-ranker + hierarchical retrieval    │
        │      • Technique-ID INVARIANT resolves against the PINNED version       │
        │      • re-ingested by a named owner on ATT&CK releases (~2x/yr)         │
        │                                                                        │
        │  (ii) APPEND-ONLY PROVENANCE-TRACKED ARTIFACT STORE ── sign-off gated ──│
        │      • D2 chains, D3 trees, D4 scenarios as retrievable objects         │
        │      • each object: provenance + typed confidence + run_id + kg_version │
        │      • reused as CONFIDENCE-WEIGHTED HYPOTHESES, never as grounding      │
        │      • deprecation-migration path on ATT&CK releases                    │
        │                                                                        │
        │  (iii) PROMOTED-EDGES OVERLAY  ── OFFLINE curation gate ONLY ──          │
        │      • versioned, human-curated; read by Tier-1 as grounding            │
        │      • tagged provenance=promoted, CONFIDENCE-CAPPED                     │
        │      • multi-sign-off / quarantine; NEVER written by runtime interrupt() │
        │                                                                        │
        │  ONE indirect-prompt-injection ingestion boundary                       │
        │  ONE audit/trace schema (deterministic replay @ pinned kg_version,      │
        │    typed per-claim confidence record)                                   │
        └───────────────┬────────────────────────────────────────────────────────┘
              read-only grounding  │  write-with-sign-off artifacts
        ┌──────────┬──────────┬────┴─────┬──────────┬──────────┐
        ▼          ▼          ▼          ▼          ▼
   ┌─────────┐┌─────────┐┌─────────┐┌─────────┐┌─────────────┐
   │ D1      ││ D2      ││ D3      ││ D4      ││ D5          │
   │ STRIDE  ││ Attack  ││ Attack  ││ Diamond ││ Hunting     │
   │ /PASTA  ││ chains  ││ trees   ││ scenarios││ COPILOT    │
   │ +critic ││ +critic ││ +critic ││ +critic ││ +critic     │
   │ (det.)  ││ (det.)  ││ (sem.)  ││ (sem.)  ││ (sem.)      │
   └────┬────┘└────┬────┘└────┬────┘└────┬────┘└──────┬──────┘
   PROVEN CORE (Stage 1 MVP) │  SPECULATIVE SYNTHESIS (earn it; §A)
        │          │          │          │            │
        └──────────┴──────────┴────┬─────┴────────────┘
                                   │ PivotRequest (typed; append-list reducer)
                                   ▼
            ┌────────────────────────────────────────────────────┐
            │  DISPATCHER = PARENT StateGraph (B1)                  │
            │   pipelines = SUBGRAPHS via Command(goto) / Send     │
            │   Tier 1: deterministic KG-frontier retrieval +       │
            │           FROZEN non-LLM re-ranker (EDGE-BOUND)       │
            │   Tier 2: bounded OPEN-GENERATION reasoner             │
            │           ONLY when max re-rank score < τ  (C3)       │
            │   default tier set by INSTRUMENTED τ-SWEEP (falsifiable)│
            │                                                       │
            │   GATE NODE (after fan-out; batches interrupts):      │
            │     • surface EVIDENCE, not a verdict                 │
            │     • mandatory KG-object citation                    │
            │       → off-graph = HALLUCINATION guard (B6), not      │
            │         an injection defense                          │
            │     • critic re-check BEFORE the human                │
            │     • TYPED confidence record + decision RULE (C4)     │
            │       — NEVER silently deny; genuine miss ESCALATES   │
            │   interrupt() ONLY on side-effecting steps (B2)       │
            │   Command(resume=...) keyed by correlation_id /        │
            │     interrupt-id resume-map                           │
            │   validated pivots → OFFLINE curation → overlay (C1)  │
            └────────────────────────────────────────────────────┘
                                   │
                                   ▼   HUMAN IS ALWAYS THE DISPOSER
```

---

### 2.1 The N per-task deterministic graphs

Each is its own LangGraph `StateGraph`. The **framework is the control flow**; the LLM only does bounded classification/drafting inside fixed nodes (guided ATT&CK task-tree reasoning hit 71.8–78.6% of subtasks vs 13.5–16.5% self-guided, arXiv:2509.07939 `[SELF-REPORTED, OFFENSE PROXY]` — note: the *directional* effect transfers; the **86–206% resource-reduction magnitude is an offense-side pentest proxy and is NOT repeated here as a defensive-task fact** (doc 06 §C); corroborated directionally by MAST and the Cyber Defense Benchmark, both `[PRIMARY]`). Each carries a **per-task externally-grounded critic** — never self-reflection alone (the self-critique paradox, arXiv:2310.01798 `[PRIMARY]`; MAST `[PRIMARY]` locates failures disproportionately in verification).

**Critics are now SPLIT by type (C5):** *deterministic structural* critics (D1 coverage, D2 precondition-as-reachability) make no LLM judgment and are replayable; *semantic* critics (D3, D4, D5) make a judgment that, absent ground truth, risks correlated error with the proposer. Semantic critics carry **independence levers** and a **release gate** (see §2.4).

| Graph | Framework spine | Topology | Key LangGraph primitives | Critic (type) |
|---|---|---|---|---|
| **D1 — STRIDE/PASTA** | STRIDE (+ ASTRIDE's "A" AI-agent category) over a DFD; PASTA stages | Orchestrator-worker; **`Send` fan-out per DFD element** | `StateGraph`, `Send`, fixed reducer | **Coverage critic — DETERMINISTIC structural.** Verifies every DFD element received every applicable STRIDE category. No LLM judgment. |
| **D2 — ATT&CK attack-chain** | Kill-chain / ATT&CK tactic ordering as a **deterministic task tree** | **Guided single agent** on the task tree (single-agent best per LangChain benchmark `[PRIMARY]`) | `StateGraph` with task tree as edges; bounded LLM node per phase | **Precondition critic — DETERMINISTIC structural.** Reframed as a **graph-reachability check**: each technique's preconditions must be reachable from the prior phase's postconditions in the pinned KG. No LLM judgment. |
| **D3 — Recursive AND/OR attack-tree** | DefenseWeaver-style role decomposition `[SELF-REPORTED, real deployment]` | **Recursive orchestrator-worker**: `Send` fan-out per frontier node; depth-bounded | `StateGraph` + recursive `Send`; depth/loop guard; reducer | **Refinement-validity critic — SEMANTIC.** Requires independence levers (§2.4). |
| **D4 — Diamond + ATT&CK** | Diamond's four vertices + ATT&CK; pivoting is core | Supervisor with bounded pivot loop; cross-task pivots → dispatcher (§2.3) | `StateGraph`; emits typed `PivotRequest` on cross-task pivots | **Pivot-consistency critic — SEMANTIC.** Confidence-weighted (attribution ≤~63% top-1, AURA `[SELF-REPORTED]`). Independence levers (§2.4). |
| **D5 — Hunting loop (COPILOT)** | Sqrrl / TaHiTI / PEAK loops; hypothesis → query → evidence → refine | **Cyclic graph**; copilot only — never autonomous (Cyber Defense Benchmark `[PRIMARY]`) | `StateGraph` with a cycle; durable execution layer (§2.5); `interrupt()` only on **side-effecting** queries (B2) | **Evidence-surfacing critic — SEMANTIC.** Presents logs/linkages without prescriptive labels (SOC field study `[PRIMARY]`). Independence levers (§2.4). |

> **D5 durability note (B-medium / B8):** checkpointers are NOT full durable execution. Day-long D5 hunts with exactly-once side-effecting actions require a **named external durable-execution layer (Temporal or Restate)** — see §2.5. Treat as a Stage-4 dependency, not a solved problem.

---

### 2.2 The THREE-store shared substrate + injection boundary + audit schema (C1, C2)

This honors Position B's "build safety/grounding once" insight **and** resolves the Rev 2 contradiction that the *same* store was both "immutable / un-poisonable" and "grows new edges from approved pivots." There is no shared *brain* — only shared *data and safety plumbing* — and the data is now **typed into three stores by trust class**.

**Store (i) — VERSIONED READ-ONLY BASE KG (no RUNTIME agent write path) (C1, C2).**
- A Neo4j-style KG linking **CVE→CWE→CAPEC→ATT&CK** (CTI-Thinker / GraphCyRAG shape `[SELF-REPORTED]`). Retrieval: off-the-shelf retrievers + a **frozen-weight non-LLM re-ranker** (B4, see below) + **hierarchical retrieval** for ~600+ technique cardinality (Hierarchical ATT&CK RAG `[SELF-REPORTED]`).
- **Versioned + content-addressed (C2).** "Immutable" is now used **only** in the precise sense: *no agent writes it at runtime.* It **does** change over time — ATT&CK re-releases ~2×/yr, CVEs land daily — so it is **re-ingested by a named owner** (RACI, §2.6) into a new content-addressed snapshot. **Every run pins a `kg_version`** recorded in the trace/artifact schema; the technique-ID invariant resolves against the **run's pinned snapshot**, not "current."
- **The technique-ID-resolution INVARIANT (hard, enforced, version-pinned).** Every ATT&CK technique ID a graph emits MUST resolve to a retrieved object **in the run's pinned `kg_version`**. An unresolved ID is a hard failure. **But resolution ≠ correctness (B5):** the invariant proves an ID maps to *some* object, not the *right* one — see §2.7 on mis-grounding.
- **Honest claim (replaces "structurally un-poisonable"):** *no runtime agent write path to the base KG.* New grounding-grade knowledge enters only through (a) an owner's re-ingestion of an authoritative release, or (b) the **offline curation gate** into store (iii) — never through the runtime `interrupt()`.

**Store (ii) — APPEND-ONLY, PROVENANCE-TRACKED ARTIFACT STORE (written ONLY with analyst sign-off).**
- D2 chains, D3 trees, D4 scenarios written here, append-only, each carrying **provenance + the typed confidence record + run_id + `kg_version`**.
- Cross-task reuse reads these **as confidence-weighted hypotheses, never as grounding**.
- **Deprecation-migration path (C2):** on an ATT&CK release, stored artifacts referencing deprecated/renamed technique IDs are flagged and migrated (or quarantined) by the artifact-curation owner (RACI, §2.6). Replay of an old artifact loads its **original pinned `kg_version`**.

**Store (iii) — PROMOTED-EDGES OVERLAY (NEW; resolves C1).**
- A **versioned, human-curated** overlay read by Tier-1 **as grounding** but tagged `provenance=promoted` and **confidence-capped** (a promoted edge can never carry base-KG-grade confidence).
- **Written ONLY via a separate OFFLINE curation gate** — multi-sign-off / quarantine review, run on a cadence by the curation owner — **NOT the runtime `interrupt()`.** A single on-graph-misdirection approval at runtime therefore **cannot** promote a malicious edge to grounding: runtime approval only writes a confidence-tagged *artifact* (store ii); promotion to the overlay requires a deliberate, audited, multi-party offline step. This is the precise fix for C1.
- Tier-1 treats overlay edges as lower-confidence grounding (the confidence cap propagates into the typed confidence record, §2.7), so even a mistakenly-promoted edge cannot masquerade as base-KG truth.

**ONE hardened indirect-prompt-injection ingestion boundary.** Single hardened entry point for adversary-controlled artifacts (CTI, web, logs) — OWASP LLM01 `[PRIMARY]`. Defenses applied once: least-privilege tooling, input/output filtering, deterministic pseudonymization (Policy-Guided shape `[SELF-REPORTED]`), adversarial testing. *Honest limit: it stops pattern-matchable payloads; it does not stop a semantically plausible, cleanly-grounding malicious pivot — see §6.*

**ONE audit/trace schema (deterministic replay @ pinned `kg_version`; typed confidence record).** Every node decision, every gate approve/edit/reject, and *which artifact informed which decision* is a logged, replayable trace node carrying **`run_id`, `kg_version`, and the typed confidence record (§2.7)**. **Replay loads the pinned snapshot, not "current"** (C2) — this is what makes "deterministic replay" actually hold across ATT&CK releases.

---

### 2.3 Cross-task coupling: the dispatcher as a parent `StateGraph` (B1, B2, C3, C4)

This is the synthesis's center of gravity — **and the least-evidenced part of the design (§A).** It is the only cross-task coordination layer and is a *fixed orchestration graph*, not an autonomous agent.

**Topology (B1).** The dispatcher is a **parent `StateGraph`**. Each per-task pipeline (D1–D5) is a **subgraph** invoked via `Command(goto=<subgraph>)` or `Send(<subgraph>, payload)`. **"Independent" is redefined** (B1): pipelines are **independently-authored, separately-testable modules** — *not* separate runtimes with an external broker. This removes the Rev 2 tension between "independent graphs" and "one dispatcher they hand pivots to."

**The `PivotRequest` type (B1).** A pivot is a typed object, not an undefined "event":
```
PivotRequest {
  origin_graph:      str          # e.g. "D5"
  correlation_id:    str          # routes the resume back to the originator
  finding:           Finding      # what triggered the pivot
  kg_citations:      [KGRef]      # the base/overlay objects cited (with kg_version)
  confidence_record: ConfidenceRecord   # typed; see §2.7
}
```
Concurrent pivots from a fan-out accumulate via an **append-list reducer** on the dispatcher state (`Annotated[list[PivotRequest], operator.add]`), so simultaneous `PivotRequest`s from multiple subgraphs do not clobber each other.

**Tier 1 — deterministic KG-frontier retrieval + FROZEN non-LLM re-ranker (the common case; EDGE-BOUND) (B4).** A deterministic traversal of the base KG + promoted-edges overlay for candidates adjacent to the finding (`uses`/`related`/`detects`/`mitigates`; Diamond's vertices; CWE→CAPEC→ATT&CK fan-out), followed by a **non-LLM, frozen-weight re-ranker** (a cross-encoder or learned-to-rank model with pinned weights). **This is the B4 fix:** the determinism / cost / replay claims hold *only* with a frozen non-LLM re-ranker. (TechniqueRAG's re-ranker is *LLM-based* `[SELF-REPORTED]` and is **not** the design's choice. If an LLM re-ranker is ever substituted, the claim **downgrades** to "replayable given a pinned model version + cached I/O," and the per-run cost rises accordingly — stated, not hidden.)

**Tier 2 — bounded OPEN-GENERATION reasoner, fired ONLY on a genuine KG-miss (C3).** **"Miss" is now defined concretely:** `max re-ranker score over the k-hop KG frontier < τ`, where **τ is a tunable threshold**. On a miss, a bounded reasoner suggests **one** candidate sibling subgraph with retrieved grounding + a typed confidence record. **It proposes a single edge and stops; it never completes a hunt.**

**Default tier set by an instrumented τ-SWEEP — and FALSIFIABLE (C3).** We do **not** report a single miss-rate number. We **sweep τ** (offline in the §A spike, then in production) and plot miss-rate vs τ. The **falsifiable prediction is explicit:**
> If the miss-rate at a sane τ is **high**, the tiered KG-first design is **wrong**, and a **reasoner-first (Position-B-like) design was right.** The design does **NOT** claim victory under all outcomes. (Rev 2's "degrades gracefully to reasoner-heavy" was an unfalsifiable hedge — it quietly *became* Position B while claiming to refine it away. Rev 3 calls that outcome what it is: a refutation of the tiered shape.)

**Default-tier promotion decision rule (C3) — WITH a human gate.** Tier-2 is expensive, so there is **no auto-promotion** of the default tier. The rule:
> *Propose* a default-tier change when the τ-sweep shows the fast-path coverage at the chosen τ is stable over a review window AND the false-approval rate (test B) at that τ is within bounds. The **floor-tuning owner** (RACI, §2.6) reviews and approves the change at a human gate. No metric auto-flips the default.

**The GATE NODE — typed confidence record + decision RULE; never silently deny (C4).** The Rev 2 scalar "confidence floor" was unbuildable (no calculus to combine non-composable sources) and self-defeating (it silently denied the rare genuine miss while passing the plausible decoy). Replaced with a **typed confidence record + a rule over it**:
```
ConfidenceRecord {
  retrieval_relevance:        float        # re-ranker score over the frontier
  attribution_class_ceiling:  float        # e.g. fine-grained actor ≤ ~0.63 (AURA)
  reuse_chain_confidences:    [float]      # confidences of any reused artifacts
  critic_verdict:             {pass, fail, abstain}
  provenance:                 {base, promoted, artifact}   # promoted is capped
}
```
**Decision rule (C4):**
- A **genuine KG-miss ESCALATES regardless of confidence** — it is surfaced to human + reasoner. This resolves the Rev 2 contradiction (the spec called a miss "the most interesting observation a hunt can produce," then silently denied it). The high-value miss is **always surfaced**.
- **Default-deny applies ONLY to high-volume, low-novelty, ON-GRAPH proposals** — `deny if provenance∈{base,promoted} AND retrieval_relevance < τ_lo AND novelty_low AND critic_verdict≠pass`.
- **Nothing is silently denied.** Every below-threshold item is **logged and counted** (a denied-items ledger), so the deny rate is itself a monitored metric, not a black hole.
- **Calibration first (C4):** no threshold (`τ`, `τ_lo`, the attribution cap) is set until confidence is **calibrated against a held-out corpus with a reliability diagram**. An uncalibrated confidence number must not gate anything.

**The GATE is layered on top of the rule:**
1. **Surface EVIDENCE, not a verdict** (SOC field study `[PRIMARY]`: only 4% of analyst queries sought a judgment — note this stat is from *voluntary, low-stakes* use and is being applied with caution to *mandatory, high-stakes* gating, see §6).
2. **Mandatory KG-object citation → off-graph proposals flagged as a HALLUCINATION GUARD (B6), not an injection defense.** A failure-to-ground tells you the model *fabricated* — it does **not** catch a rational injector, who steers toward a *real, on-graph, citable* decoy (§6). Rev 2 over-claimed this as an "off-graph injection detector"; Rev 3 reframes it honestly.
3. **Independent critic re-check BEFORE the human** (the semantic critics carry independence levers, §2.4).
4. **The typed-confidence decision rule above** (not a bare scalar).

**Gate ONLY on side-effecting steps (B2).** A **read-only query against already-authorized telemetry does NOT `interrupt()`.** Only **externally-acting / side-effecting** steps interrupt: containment actions, external enrichment calls, any write. Disposition is **batched and checkpointed at natural decision boundaries** (e.g., after a hunt phase, not after every query). This fixes the Rev 2 throughput collapse where a day-long D5 hunt produced dozens-to-hundreds of gate stops on the SOC's most contended resource.
- **Multi-interrupt batching (B1):** after a fan-out, a **single gate node** collects all pending interrupts; resume is a **resume-map keyed by interrupt ID**, and routing back to each originating subgraph uses `Command(resume=...)` keyed by `correlation_id`.
- **Queue-overflow / shift-change policy (B2):** if the gate queue exceeds a threshold or a shift changes, the dispatcher checkpoints and pauses new fan-outs (durable execution, §2.5) rather than spawning unbounded pending interrupts; pending dispositions carry over to the next analyst with full context.

**Promotion loop (C1 — now OFFLINE).** A Tier-2 proposal the analyst approves at runtime is written to the **artifact store (ii)** as a confidence-tagged hypothesis. Promotion of a recurring, validated pattern to a **grounding-grade overlay edge (store iii)** happens **only through the separate offline curation gate** (multi-sign-off / quarantine), never the runtime `interrupt()`. The system gets cheaper over time as the long tail is *curated*, not as agents write grounding.

**Explicitly FORBIDDEN** (unchanged from prior rounds, plus C1):
- Always-on autonomous supervisor (Cyber Defense Benchmark `[PRIMARY]`).
- Ungated **side-effecting** agent-to-agent collaboration (read-only coordination is allowed, B2).
- Autonomous hunting / autonomous disposer.
- **Any runtime agent write to the base KG or the promoted-edges overlay** — overlay writes go only through the offline curation gate.

---

### 2.4 Critic independence levers + release gate (C5)

- **Deterministic structural critics (D1 coverage, D2 precondition-as-reachability)** make no LLM judgment; they are replayable graph/set checks. These can gate from day one.
- **Semantic critics (D3, D4, D5)** make a judgment that, grounded against the *same* KG the proposer used, risks **correlated error** (the self-critique paradox). They MUST carry at least one **independence lever**:
  - a **different model** from the proposer, or
  - a **different grounding view** (e.g. a different retrieval slice / hierarchy level), or
  - **reduction to constraint-satisfaction** (turn the judgment into a checkable constraint where possible).
- **Per-pipeline release gate (C5):** each critic's **false-confirmation rate** is measured, and the pipeline runs in **shadow mode (no gating authority) until that rate clears a stated bound.** A critic with an unknown error rate has no gating authority. This ties the §5 measurement to deployment, which Rev 2 left dangling.

### 2.5 Durable execution + interrupt idempotency (B-medium)

- **Named dependency:** day-long D5 hunts use a **durable-execution layer (Temporal or Restate)**, not bare checkpointers. This is a Stage-4 dependency, validated before reliance (Open Problem 4).
- **Idempotency vs audit logging (fixed):** appending a trace node *before* `interrupt()` double-logs on resume. So: **side effects and their trace appends happen strictly AFTER the interrupt resolves**, and **every external query carries an idempotency key** so a resume re-executes nothing and re-logs nothing.

### 2.6 Day-2 operations RACI (doc 06 §C)

| Responsibility | Owner (R/A) | Notes |
|---|---|---|
| **Base-KG ingestion + versioning** | KG-ingestion owner | Re-ingests ATT&CK releases (~2×/yr) into new content-addressed `kg_version` snapshots; runs the deprecation-migration. |
| **5 critic monitors** | Per-pipeline critic owners | One monitor per critic; track false-confirmation rate; hold shadow-mode release gate (§2.4). |
| **Confidence-floor / τ tuning** | Floor-tuning owner | Owns calibration (reliability diagram), τ-sweep review, and the human gate on default-tier changes (C3/C4). |
| **Injection-rule updates** | Injection-rule owner | Maintains ingestion-boundary filters + adversarial test set. |
| **Artifact-store curation + promoted-edges overlay** | Artifact-curation owner | Runs the **offline promotion/curation gate** (C1); migrates/quarantines artifacts on KG releases (C2). |

### 2.7 Mis-grounding as a first-class failure mode (B5/B6)

- **"Grounds to SOME object" ≠ "grounds to the CORRECT object."** At ~600-technique cardinality with re-ranker accuracy plausibly ~60–70%, **routine mis-grounding** to a plausible-but-wrong technique is indistinguishable to the off-graph detector from a correct grounding — the *same* hole as on-graph misdirection, but from **ordinary error, not an adversary**.
- **We measure re-ranker ACCURACY, not just resolution success** (B5) — see §5 and the §A.2 spike. The technique-ID invariant only checks resolution; accuracy is a separate, mandatory metric.
- **The off-graph detector is a HALLUCINATION guard (B6), not an injection defense.** A rational injector picks an on-graph decoy; the detector catches the fabrication nobody would bother with. The injection story is honestly covered only by the (unproven) human gate + shadow-channel canaries (§6).

---

## 3. Why This Won on the Rubric (honest, post-red-team)

Mapping the converged design to each weighted criterion. **Where the red-team weakened a claim, the language below is honest rather than triumphant.**

### Feasibility / buildability — 25 (held by A; backbone — but only the PROVEN CORE is "settled")
Built from documented LangGraph primitives — `StateGraph`, `Send`, `Command`-routing, subgraphs, `interrupt()`, durable execution `[PRIMARY, official docs]`. Deployment-proven prior art is uniformly narrow and deterministic: **DefenseWeaver** (D3) and **ASTRIDE/STRIDE-GPT** (D1) `[SELF-REPORTED, real deployment]`. **Honest re-frame (B3):** *only D1+D3 are deployment-proven.* The dispatcher/tiering/promotion/D4/D5 are the most-extrapolated parts; their feasibility is **conditional on the §A.2 spike**, not asserted. The instrument-then-decide discipline is a feasibility win *because it can return "don't build it."*

### Reliability & safety (incl. HITL) — 25 (R6 even — and now SOFTENED by C1/C4/C6)
- Deterministic framework-as-state-machine eliminates MAST's largest failure class within each graph.
- Verification, not self-reflection: externally-grounded critics, now **split** (deterministic vs semantic) with **independence levers + a shadow-mode release gate** (C5).
- **C1 honesty:** the safety pillar is **no runtime agent write path to grounding** — *not* "structurally un-poisonable." Promotion is an explicit, audited, offline curation surface; the overlay is confidence-capped.
- **C4 honesty:** the gate is a **typed confidence record + rule**, not a scalar floor; it **never silently denies**; genuine misses **always escalate**.
- **C6 honesty:** **HITL efficacy is UNFALSIFIED, not validated.** The Cyber Defense Benchmark is silent on whether a human catches a fluent, well-grounded-but-wrong proposal. The "4% sought verdicts" stat is *voluntary, low-stakes* and is applied cautiously. A pre-registered **kill-criterion** exists (§5). This criterion is satisfied *because* the mechanism AND its unproven status are on record — not because the gate is proven.

### Evidential grounding — 20 (B edged it; mis-grounding now named)
Strongest primary evidence flagged honestly (2509.07939 = `[SELF-REPORTED, offense proxy]`, magnitude not transferred; SOC field study, OWASP, MAST, Cyber Defense Benchmark `[PRIMARY]`). **CyberLLM-FINDS is now cited neutrally (doc 06 §C):** KG+GNN 8.00 vs RAG 7.87 is a 0.13 margin and RAG won 3 of 5 judged categories — it is *not* a clean KG win and is not used as one. **B5 added:** mis-grounding is a first-class failure mode and re-ranker *accuracy* is measured, not just resolution.

### Cost / latency — 12 (held by A — SOFTENED by B4)
The cost win holds **only with the frozen non-LLM re-ranker (B4).** The Rev 2 claim implicitly rested on TechniqueRAG's *LLM* re-ranker, which is neither deterministic nor free. With a frozen cross-encoder, Tier-1 is cheap and replayable. **B8 honesty:** the on-graph-misdirection defenses are **not free** — N-parallel hypotheses multiply the ~$18/run baseline *and* the gate load N×; analyst rotation needs staffing; canaries need a shadow channel. These are costed (§6), not assumed away. The ~$18/run benchmark `[PRIMARY]` remains the cautionary baseline.

### Extensibility — 10 (B won it; promotion now offline)
The base KG grows by **owner re-ingestion**; novel coupling is surfaced by Tier-2 and folded in **only via the offline curation gate** into the confidence-capped overlay (C1) — not by runtime writes. Artifacts reused as confidence-weighted hypotheses. Adding a task = one new graph + critic + event types.

### Auditability — 8 (A's discipline — SOFTENED by C2)
Common-case pivots log a deterministic, replayable trace. **C2 honesty:** deterministic replay holds **only because** every run pins a `kg_version` and replay loads the **pinned snapshot, not "current"** — Rev 2's "immutable KG" silently broke replay on the next ATT&CK bump. The audit schema now carries `kg_version` + the typed confidence record + which artifact informed which decision.

---

## 4. Staged Build Roadmap (re-sequenced per B3)

**Stage 0 — Integration substrate (B7, NEW — a requirement, not a nicety).**
- Gates deliver into the **existing approval queue** (XSOAR / ServiceNow / equivalent), not a bespoke interrupt-UI analysts must watch separately.
- Telemetry is queried via **existing SIEM/EDR APIs (Splunk/Sentinel/CrowdStrike) under existing RBAC.**
- Outputs are emitted in formats the **existing tools consume.** Without this, the system is routed around within a week.

**Stage 1 — D1 + D3 MVP (the proven core; SHIPPABLE and DECISION-GATED; §A).**
- Build D1 and D3, each with its **deterministic structural critic**, a minimal audit/trace schema (with `kg_version` from day one to avoid retrofit churn, doc 06 §C), a minimal injection boundary, and Stage-0 integration.
- **No dispatcher, no Tier-2, no KG substrate beyond a lightweight reference index, no cross-task coupling, no promotion loop.**
- **DECISION GATE (§A.2):** ship, measure expert-rated value, AND run the offline spike (miss-rate τ-sweep + re-ranker accuracy on a historical corpus). **A high miss-rate or low re-ranker accuracy vetoes the substrate/dispatcher** and sends the design back to the drawing board.

**Stage 2 — THREE-store substrate (only if Stage-1 gate passes).**
- Build the **versioned, content-addressed read-only base KG** + retriever + **frozen non-LLM re-ranker** + hierarchical retrieval. No runtime agent write path.
- Implement the **version-pinned technique-ID invariant** and **re-ranker accuracy** harness.
- Stand up the **append-only sign-off-gated artifact store** (with `kg_version` + deprecation-migration) and the **promoted-edges overlay + offline curation gate**.
- Name and stand up the **durable-execution layer** (Temporal/Restate).
- Finalize the **one audit/trace schema** (replay @ pinned `kg_version`; typed confidence record). Retrofit D1/D3.

**Stage 3 — D2 + D4, dispatcher + instrumentation.**
- D2 (guided single agent + deterministic precondition-as-reachability critic) and D4 (Diamond pivot loop + semantic pivot-consistency critic with independence levers).
- **Dispatcher = parent `StateGraph`; pipelines = subgraphs** (B1). `PivotRequest` type, append-list reducer, `correlation_id` resume-map, multi-interrupt batching.
- **Gate node** (typed confidence rule, evidence-first, hallucination-guard citation, critic re-check) wired on **side-effecting steps only** (B2); queue-overflow / shift-change policy.
- **τ-sweep miss-rate instrumentation on from day one**; default tier set by the human-gated rule (C3).
- Promotion routed to the **offline curation gate** (C1).

**Stage 4 — D5 hunting copilot LAST (highest risk, lowest autonomy).**
- D5 cyclic graph, copilot only, on the durable-execution layer; **read-only telemetry queries do not interrupt** (B2).
- Validate durable execution for day-long hunts before reliance.

**Sequencing rationale:** prove the core (Stage 1) → decision gate → substrate → dispatcher → D5. No always-on supervisor is ever built. The speculative synthesis is *earned*, not assumed.

---

## 5. Evaluation Plan

No ground truth for completeness (Open Problem 1), so evaluation is layered; the offline spike (§A.2) precedes the dispatcher.

**Layer 1 — LLM-as-judge** (regression, not go/no-go; inherits the self-critique paradox).

**Layer 2 — Expert evaluation** (the real bar). Comparative + coverage metrics vs manual baselines (DefenseWeaver shape `[SELF-REPORTED]`). This is the **Stage-1 MVP value gate** (§A.2).

**Layer 3 — Holdout benchmarks.** Cyber Defense Benchmark `[PRIMARY]` (D5 ceiling), DefenderBench `[PRIMARY]`, ATT&CK-mapping accuracy + **re-ranker ACCURACY** (B5, not just resolution) and AURA-style attribution.

**Mandatory test A — the MISS-RATE τ-SWEEP (sets the default tier; C3).** Run **first offline on a historical corpus** (§A.2), then in production from Stage 3. Plot miss-rate vs τ. **State the falsifiable result:** a high miss-rate at sane τ refutes the tiered design and indicates a reasoner-first design was right. The default tier changes **only via the floor-tuning owner's human gate**, never auto-promotion.

**Mandatory test B — on-graph FALSE-APPROVAL-RATE (the residual the detector is blind to).** Built as a **seeded-decoy lab benchmark** (synthetic ground truth) — an explicit **lower-bound proxy**; production exposure is unmeasurable without an oracle (doc 06 §C). Plant on-graph misdirection (real, cleanly-grounding decoy techniques) and measure analyst false-approval. Also measures whether **evidence-first framing actually reduces rubber-stamping** (unproven, C6) and instruments **analyst dwell-time per gate** (the rubber-stamp tell). Run at both tiers.

**Pre-registered KILL-CRITERION (C6, NEW).**
> If test B shows that evidence-first framing does **not** beat verdict-framing AND the on-graph false-approval rate exceeds a stated threshold X%, then **LOWER autonomy** (e.g. add a second reviewer, narrow what the copilot may surface, or pull a task back to advisory-only) — do **not** hold autonomy. HITL is treated as a hypothesis under test, not a proven safeguard.

**Deployment bars — what would (and would NOT) permit raising autonomy.**
- **WOULD (narrowly) only if** *all of*: holdout benchmark clears its bar; the per-task critic's false-confirmation rate has cleared its **shadow-mode release gate** (C5); the test-B on-graph false-approval rate is within bounds; expert eval confirms on held-out cases; confidence is **calibrated** (C4). Even then the change is narrow (e.g. auto-promote one enumerated event-type), never blanket.
- **WOULD NOT:** open-ended hunting, autonomous attribution (≤~63% top-1), removing the `interrupt()` gate on any **side-effecting** step, or any runtime agent write to the base KG or overlay. Structural bars, not prompt-tunable.

---

## 6. Caveats & Autonomy Ceiling

Honest limits, carried from the brief's Open Problems, the debate's concessions, and the red-team review.

1. **No autonomous hunting — ever, under current evidence.** Cyber Defense Benchmark `[PRIMARY]` (none of 11 frontier models passed; ~0.46 coverage; ~$18/run, specifically Opus 4.6). D5 is a copilot; the reasoner proposes one edge and stops; the human is always the disposer.

2. **On-graph misdirection injection (irreducible) — and the off-graph detector does NOT defend against it (B6).** The off-graph detector is a **hallucination guard**: it fires when a pivot *fails* to ground. A rational injector steers toward a *real, on-graph, citable* decoy — which passes the citation check, the critic, and surfaces clean. **Grounding proves a technique is REAL, not RELEVANT or UNMANIPULATED.** No architecture in the brief closes this. **Mitigations are costed honestly (B8):** decoy/canaries **via a shadow channel only — never production telemetry** (production canaries pollute detections, fire real SOAR, and create audit/compliance problems); N independent parallel hypotheses **multiply per-run cost AND gate load N×**; analyst rotation **requires a staffed pool of interchangeable senior hunters most SOCs lack and breaks hunt continuity**. If those costs are not paid, **downgrade the claim to "bounded blast radius + post-hoc audit,"** not "defended."

3. **Mis-grounding from ordinary error (B5) — same blind spot, no adversary needed.** At ~600-technique cardinality with ~60–70% plausible re-ranker accuracy, routine mis-grounding to a plausible-but-wrong technique is indistinguishable to the detector from a correct one. We measure re-ranker **accuracy** (§5), not just resolution.

4. **Automation bias survives at BOTH tiers, and evidence-first is UNFALSIFIED, not validated (C6).** Automation bias is a property of the human. Whether evidence-first framing reduces rubber-stamping is **empirical and unproven**; surfacing evidence may even *increase* bias by lending false thoroughness under time pressure. The "4% sought verdicts" stat is from *voluntary, low-stakes* use and is mis-applicable to *mandatory, high-stakes* gating. Hence the pre-registered kill-criterion and dwell-time instrumentation (§5).

5. **The promotion surface is an audited OFFLINE risk, not a closed one (C1).** Promotion to the grounding overlay is multi-sign-off / quarantine and confidence-capped, with no runtime write path — but it is still a human-curation surface and must be monitored (artifact-curation owner, §2.6).

6. **KG versioning is operational, not free (C2).** ATT&CK releases (~2×/yr) require re-ingestion, artifact migration/quarantine, and replay against pinned snapshots. Unowned, this silently breaks deterministic replay.

7. **Threat-model / attack-tree coverage has no ground truth** (Open Problem 1). Evaluation is comparative + coverage-based; the τ-sweep miss-rate is an empirical proxy, not a completeness oracle.

8. **The self-critique paradox** (arXiv:2310.01798 `[PRIMARY]`). Semantic critics carry independence levers (§2.4); the false-confirmation rate is the real bottleneck and gates deployment via shadow mode (C5).

9. **Attribution ceiling ≤~63% top-1 (fine-grained).** AURA `[SELF-REPORTED]` (gpt-4o 63.33% top-1 / 73.33% top-2 over 150+ groups). Fine-grained attribution is **always** a confidence-weighted hypothesis (the `attribution_class_ceiling` field, §2.7), never asserted fact.

10. **The framework-vs-synthesis confidence boundary (re-framed, B3).** The deterministic, single-domain proven core (D1, D3, the version-pinned technique-ID invariant, the three-store substrate's read side, the Tier-1 frozen re-ranker) rests on the strongest evidence. **The entire coupling synthesis — dispatcher, tiering, Tier-2 reasoner, promotion, D4, D5 — is the most-extrapolated, least-evidenced part of the design, and must be EARNED via the §A.2 decision gate, not presented as co-settled.** Its central component, the Tier-2 open-generation reasoner, has no end-to-end source in the brief.

11. **Durable execution for long hunts is a named dependency, not solved** `[WEAK/CONTESTED]`. Day-long D5 hunts need Temporal/Restate (§2.5); validate before reliance (Open Problem 4).

12. **Cost/latency is a first-class deployment gate** `[PRIMARY]`. The ~$18/run baseline, the supervisor "telephone" overhead avoided, and the B8 misdirection-defense costs all bound feasibility.

---

*Decision record complete (Rev 3). The motion was refined, not won outright — and Rev 3 honestly separates the **proven core** (D1+D3, shippable now) from the **speculative synthesis** (dispatcher/tiering/promotion/D4/D5, earned via an explicit decision gate). The two flat contradictions are resolved (C1 via a three-store split with an offline promotion gate; C4 via a typed confidence record that never silently denies). The control signal is defined and falsifiable (C3). The dispatcher is specified as a parent `StateGraph` with subgraphs (B1), gating only side-effecting steps (B2). The off-graph detector is reframed as a hallucination guard (B6); mis-grounding is a first-class failure mode (B5). HITL is unfalsified, not validated, with a pre-registered kill-criterion (C6). Integration, day-2 RACI, durable execution, and the honest cost of misdirection defenses are now requirements, not afterthoughts. The synthesis must earn its complexity — instrumented-first — before it is built.*
