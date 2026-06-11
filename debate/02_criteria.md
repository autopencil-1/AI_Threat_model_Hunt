# 02 — Debate Criteria & Rulebook
## Most Feasible Architecture for AI Agents in Threat Modeling and Threat Hunting

This is the binding rulebook for the structured debate. Both debaters argue from the shared evidence in `01_background_research.md` and the reference doc. The Background Researcher (author of this file) remains strictly neutral and does not argue either side.

---

## MOTION

> **"For a security team building AI agents across threat modeling and threat hunting today, the most feasible architecture is a portfolio of narrow, per-task deterministic pipelines — each framework-as-state-machine, retrieval-grounded, paired with an independent critic, and human-gated — deployed incrementally, rather than a single unified supervisor/hierarchical multi-agent platform spanning all tasks."**

Position A affirms the motion. Position B opposes it. The debate resolves which architecture is **most feasible** (buildable, reliable, affordable, auditable, and extensible) given 2024–2026 evidence — not which is most ambitious or most capable in principle.

---

## POSITION A — "Narrow deterministic pipelines, human-gated, incrementally deployed"
**(Debater 1 — affirms the motion)**

**Thesis:** Build the system as a *portfolio of independent, task-specific deterministic graphs*, sequenced by confidence. Each design (D1 STRIDE/PASTA, D3 attack-trees, then D2 chains, D4 scenarios, D5 hunting-copilot) is its own LangGraph `StateGraph` where the **framework is the control flow** and the LLM only does bounded classification/drafting inside fixed nodes.

**Concrete architecture A must defend:**
- **Topology:** deterministic orchestrator-worker (Send fan-out per DFD element / per attack-tree frontier node) for D1/D3; a *guided single agent constrained by a deterministic ATT&CK task tree* for D2; minimal supervisor only where genuinely needed (D4/D5). No cross-task unified controller.
- **Grounding:** mandatory RAG/KG over ATT&CK with the hard invariant that every technique ID resolves to a retrieved object; no shared "platform brain."
- **Verification:** a separate, externally-grounded **critic node per pipeline** (coverage check, chain-precondition check, refinement-validity check) — never self-reflection alone.
- **HITL:** `interrupt()` gate before any externally-executed query and before publishing; D5 ships as a **copilot that surfaces evidence, not verdicts**.
- **Rollout:** ship D1 and D3 first (highest confidence, deployment-proven blueprints), add ATT&CK retrieval infra, then D2/D4, then D5 last.

**Evidence A leans on:** guided ATT&CK task tree 71.8–78.6% vs self-guided 13.5–16.5% on weak models at lower cost (arXiv:2509.07939); MAST locates failures in coordination/verification that deterministic graphs avoid (arXiv:2503.13657); the SOC field study shows analysts want evidence not verdicts, only 4% ask for judgments (arXiv:2508.18947); Cyber Defense Benchmark shows open-ended autonomy fails (none passed); DefenseWeaver/ASTRIDE prove narrow pipelines deploy in production. Single-agent scaled poorly only as the *tool surface* grew (LangChain benchmark) — which narrow scoping deliberately avoids.

---

## POSITION B — "Unified supervisor/hierarchical multi-agent platform across all tasks"
**(Debater 2 — opposes the motion)**

**Thesis:** Build one **unified supervisor/hierarchical multi-agent platform** with shared infrastructure (one ATT&CK knowledge layer, one memory/Store, one durable checkpointer, one audit/trace plane) and a top supervisor that routes to task sub-graphs and lets specialist agents collaborate, pivot, and share context across threat-modeling and hunting. Per-task pipelines are *modules within* this platform, not isolated silos.

**Concrete architecture B must defend:**
- **Topology:** hierarchical — a top supervisor routes to per-domain supervisors (modeling vs. hunting), each managing specialist agents (TTP-extractor, sequencer, Diamond-pivoter, hypothesis-generator, query-generator, critic). Sub-graphs reuse one another (e.g., D3 attack-trees feed D4 scenarios; D2 chains feed D5 hypotheses).
- **Shared state:** one cross-task memory/Store and one knowledge graph so a hunt can reuse a threat model's outputs and vice versa — the value of unification is cross-task context.
- **Verification & HITL:** independent critic agents and HITL interrupts are *retained* (B is not arguing for unsafe autonomy) — but implemented once, platform-wide, with consistent audit/trace and consistent injection defenses.
- **Why unify:** the LangChain benchmark shows single/narrow agents "fall off sharply" as scope grows and that supervisor/swarm stay stable; a portfolio of silos duplicates retrieval, memory, audit, and safety plumbing and cannot share context; coordinated multi-agent triage (CORTEX) and policy-gated hunting demonstrate collaborating-agent value.

**Evidence B leans on:** LangChain multi-agent benchmark (multi-agent scales, single-agent doesn't, supervisor/swarm stable); CORTEX collaborating agents reduce false positives with auditable decisions (arXiv:2510.00311); Policy-Guided Threat Hunting shows a working multi-agent SOC team with gating + HITL (arXiv:2603.23966); shared KG retrieval (CVE→CWE→CAPEC→ATT&CK) is most valuable when reused across tasks; MAST's fixes (verification + structured coordination) are achievable *within* a disciplined platform and need not force fragmentation.

---

## The genuine fork

A and B agree on the non-negotiables (retrieval grounding, independent critics, HITL gates, no autonomous hunting, no swarm-for-its-own-sake). They **disagree on scope and coordination**: A says feasibility today means *minimizing coordination surface* — many small deterministic graphs, shipped incrementally, each independently auditable. B says feasibility at *team scale* means *one disciplined platform* — shared infra, cross-task context reuse, supervisor/hierarchical routing — because silos don't scale and can't share what they learn. Both are defensible from the evidence; the debate decides which wins on the weighted rubric.

---

## JUDGING RUBRIC (weights sum to 100)

| # | Criterion | Weight | What it measures |
|---|-----------|-------:|------------------|
| 1 | **Feasibility / buildability** | 25 | Can a real team build and ship this *now* with current models, frameworks (LangGraph), and proven blueprints? Realistic effort, dependency order, and deployment-proven prior art. |
| 2 | **Reliability & safety (incl. HITL)** | 25 | Resistance to MAST-style failures, error compounding, the self-critique paradox, and prompt injection; soundness of verification and human gating; honest handling of the autonomy ceiling. |
| 3 | **Evidential grounding** | 20 | How directly the architecture's claims are backed by `01_background_research.md` — strong primary/benchmark evidence vs. self-reported or extrapolated claims; honesty about evidence quality. |
| 4 | **Cost / latency** | 12 | Token/compute/latency burden (supervisor translation overhead, multi-agent hops, retrieval cost) vs. value delivered; efficiency on weaker/cheaper models. |
| 5 | **Extensibility** | 10 | Ease of adding a new task/framework, reusing components, and sharing context/knowledge across tasks without rework. |
| 6 | **Auditability** | 8 | Traceability of every decision, deterministic replay, confidence-weighting of claims, and reviewability by a human analyst and an auditor. |

**Strong vs. weak per criterion:**
- **Feasibility (25):** *Strong* — maps to documented LangGraph primitives + deployment-proven prior art (DefenseWeaver, ASTRIDE, Policy-Guided), with a credible build order. *Weak* — relies on capabilities no current system demonstrates, or hand-waves integration effort.
- **Reliability & safety (25):** *Strong* — independent externally-grounded critic, HITL before external action, explicit injection defenses, names its failure modes and mitigations, respects the Cyber Defense Benchmark ceiling. *Weak* — leans on self-reflection, assumes autonomy the benchmarks contradict, ignores indirect prompt injection.
- **Evidential grounding (20):** *Strong* — cites primary/benchmark sources and flags self-reported numbers as claims. *Weak* — treats single-paper results as proven, or asserts without citation.
- **Cost/latency (12):** *Strong* — quantifies overhead, exploits deterministic scaffolding's cheapness (arXiv:2509.07939), avoids needless hops. *Weak* — ignores token/latency cost or the ~$18/run reality.
- **Extensibility (10):** *Strong* — clean module boundaries *and* a credible cross-task reuse story. *Weak* — either rigid silos that duplicate work, or a monolith that can't add a task without global rework.
- **Auditability (8):** *Strong* — deterministic replay, per-claim confidence, full traces, human+auditor reviewable. *Weak* — opaque agent chains, no confidence values, hard-to-trace handoffs.

---

## PROTOCOL REMINDER

- **Debater 1 (Position A) speaks first each round.** Debater 2 (Position B) responds in the same round.
- **One argument per side per round.** Keep each contribution focused on a single point or rebuttal.
- **Maximum 20 rounds.** The debate may conclude earlier if positions converge or are exhausted.
- **Concessions and refinements are encouraged.** A debater may concede a point, refine their architecture in response to evidence, or narrow/sharpen their thesis — this is rewarded under the rubric, not penalized. The goal is the most feasible architecture, not rhetorical victory.
- All claims should cite `01_background_research.md` or the reference doc; flag self-reported vs. primary evidence honestly.
- The neutral researcher does not intervene in argument; the judge applies the rubric at the end.
