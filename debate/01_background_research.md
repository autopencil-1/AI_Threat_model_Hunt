# 01 — Background Research Briefing
## Architectures for AI Agents in Threat Modeling and Threat Hunting

**Role:** Neutral background researcher. This document *extends* the reference doc (`../Architectures for AI Agents in Threat Modeling and Threat Hunting.md`) with additional 2024–2026 evidence. It does not restate that doc's framework primers (STRIDE/PASTA/Diamond/kill-chain/ATT&CK/Sqrrl/TaHiTI/PEAK, LangGraph primitives) — read it for those. Every non-obvious claim below is cited inline. Confidence and evidence-quality flags are explicit. Both debaters share this as common ground.

**How to read the flags:** `[PRIMARY]` = peer-reviewed / vendor-authoritative / official docs. `[SELF-REPORTED]` = single-paper result on a small or custom eval set; treat numbers as claims, not validated facts. `[WEAK/CONTESTED]` = blog-tier, vendor-marketing, or disputed.

---

## 1. Candidate Architectures (enumerated)

The reference doc proposes **five framework-anchored designs**. We retain the same numbering so the debaters can reference them unambiguously, and add what new 2024–2026 evidence says about the *feasibility* of each.

- **D1 — STRIDE/PASTA structured threat-modeling pipeline** (deterministic orchestrator-worker; Send fan-out per DFD element).
- **D2 — Kill-chain/ATT&CK attack-chain constructor** (supervisor or guided single-agent constrained by an ATT&CK task tree).
- **D3 — Recursive AND/OR attack-tree generator** (recursive orchestrator-worker; DefenseWeaver-style roles).
- **D4 — Diamond + ATT&CK threat-scenario generator** (supervisor with a pivoting loop; confidence-weighted).
- **D5 — Hypothesis-driven hunting loop** (cyclic supervisor; Sqrrl/TaHiTI/PEAK; copilot-only).

New evidence sharpens two cross-cutting design *axes* that the debate should turn on (these, not the five designs, are the real fork — see `02_criteria.md`):

- **Axis 1 — Scope:** narrow, per-task deterministic pipelines (D1, D3 first) vs. a unified multi-agent platform spanning all five tasks.
- **Axis 2 — Coordination/control:** deterministic graph + framework-as-state-machine + independent critic + HITL gates vs. flexible LLM-driven routing (supervisor/swarm) with more autonomy.

### New systems beyond the reference doc

- **CORTEX** — Collaborative LLM Agents for High-Stakes Alert Triage (Wei et al., Sep 2025). A multi-agent SOC triage architecture: a *behavior-analysis agent* inspects activity sequences, *evidence-gathering agents* query external systems, and a *reasoning agent* synthesizes findings into an **auditable** decision. Reports "large reductions in false positives and improved reasoning quality over baselines," and releases a process-level SOC investigation dataset across 10+ real scenarios. `[SELF-REPORTED]` [source: CORTEX, arXiv:2510.00311 — https://arxiv.org/abs/2510.00311]
- **Policy-Guided Threat Hunting** (the reference doc's D5 prior art, now detailed). Three-tier system: a **DRL agent** + **autoencoder anomaly detector** *gate* LLM access (only high-priority windows, scored `DRL_Action × AAD_Score`, reach the LLM team), then an LLM team (*Senior SOC Triage Analyst* generating SPL, *Threat Intelligence Analyst* mapping to ATT&CK, *Orchestrator* writing reports). HITL: analysts validate LLM insights on Splunk before containment. Guardrails: deterministic IP pseudonymization before the LLM sees data; structured role prompts. On Boss-of-SOC (12k instances): recall 0.873 / F1 0.861 in its FP-averse mode. `[SELF-REPORTED]` [source: Policy-Guided Threat Hunting, arXiv:2603.23966 — https://arxiv.org/html/2603.23966v1]
- **ASTRIDE / STRIDE-AI / STRIDE GPT** — automated STRIDE tooling. ASTRIDE is "the first framework to both extend STRIDE with AI-specific threats and integrate fine-tuned VLMs with a reasoning LLM to fully automate diagram-driven threat modeling," adding an *"A" category for AI-agent-specific attacks* (prompt injection, unsafe tool use, memory misuse). STRIDE-AI bridges NIST AI RMF and OWASP LLM Top 10. STRIDE GPT is a deployed open-source LLM tool generating STRIDE threat models and attack trees from an app description. `[SELF-REPORTED / TOOL]` [source: ASTRIDE, arXiv:2512.04785 — https://arxiv.org/html/2512.04785; source: STRIDE-AI, arXiv:2605.17163 — https://arxiv.org/html/2605.17163v1]
- **DefenseWeaver** (D3 prior art, now with deployment data). Validated across four automotive security projects; identified **11 critical attack paths verified by penetration testing** and remediated by automakers; integrated at Xiaomi Auto and UAES; consumed ~300M tokens in 3 months generating **8,200+ attack trees**; reported to outperform manual attack-tree generation across six scenarios and to generalize to UAVs and marine navigation. `[SELF-REPORTED, but with real deployment]` [source: DefenseWeaver, arXiv:2504.18083 — https://arxiv.org/html/2504.18083v1; NDSS — https://www.ndss-symposium.org/ndss-paper/automating-function-level-tara-for-automotive-full-lifecycle-security/]

---

## 2. Topology Trade-offs (extended with new benchmark data)

The reference doc's qualitative guidance ("supervisor first, swarm only when latency-bound, avoid swarm for security work") is now backed by a controlled benchmark and a failure taxonomy.

### LangChain's controlled multi-agent benchmark
On a modified τ-bench (retail support, 100 examples, GPT-4o), tested **single-agent vs. swarm vs. supervisor** while injecting "distractor" domains:
- **Single agent** is best with *one* domain but "falls off sharply" at two or more distractor domains — i.e., it does not scale as the tool/instruction surface grows.
- **Swarm and supervisor stay stable** as distractors increase; swarm slightly outperforms supervisor on score and uses fewer tokens.
- The supervisor's "translation layer" (only the supervisor talks to the user) degrades performance like "a game of telephone." Three fixes — removing handoff messages from sub-agent context, direct message forwarding, and tool-name tuning — yielded ~**50% performance gains**.
`[PRIMARY — vendor benchmark]` [source: LangChain, "Benchmarking Multi-Agent Architectures" — https://www.langchain.com/blog/benchmarking-multi-agent-architectures]

> Debate-relevant reading: this *complicates* a naive "supervisor is always safest" claim. Single-agent wins when scope is narrow; multi-agent wins as the surface grows; supervisor's information-translation overhead is a real, measured cost. It also shows swarm is not strictly worse on accuracy — the case against swarm for security is about **auditability**, not raw score.

### Why multi-agent systems fail — MAST
"Why Do Multi-Agent LLM Systems Fail?" (Cemri, Pan, Yang et al., 2025) introduces **MAST**, a taxonomy of **14 failure modes** in **three categories**: (1) **specification issues** (unclear roles/requirements), (2) **inter-agent misalignment** (coordination breakdowns), (3) **verification challenges** (insufficient validation). Core recommendation: reliability requires **stronger verification** and **structured coordination protocols**, not just stronger individual agents. `[PRIMARY — peer-reviewed/widely-cited]` [source: arXiv:2503.13657 — https://arxiv.org/pdf/2503.13657; OpenReview — https://openreview.net/forum?id=fAjbYBmonr]

### Error compounding / self-conditioning
Secondary analyses warn of compounding: a small per-step error rate snowballs over long multi-agent chains, and an LLM that sees its own prior errors in context becomes *more* likely to repeat them ("self-conditioning"). A frequently-cited illustration: a 1%-per-token error rate compounds toward ~87% cumulative failure by token 200. `[WEAK/CONTESTED — blog-tier illustration; directional, not a measured security result]` [source: Zartis — https://www.zartis.com/the-compounding-errors-problem-why-multi-agent-systems-fail-and-the-architecture-that-fixes-it/; Augment Code — https://www.augmentcode.com/guides/why-multi-agent-llm-systems-fail-and-how-to-fix-them]

### Net topology picture for security
- Deterministic graph + framework-as-state-machine (D1, D3) sidesteps most MAST failure modes by removing free-form coordination.
- Supervisor is the production default for *routing among distinct expert roles* (D2, D4, D5), but carries token/latency overhead and an information-translation cost.
- Swarm is competitive on accuracy/latency but sacrifices the traceability security work needs; the argument against it is auditability, not capability.
- Composition is real: many production systems run a router → supervisor → (optional swarm/worker fan-out) hybrid. `[WEAK — practitioner consensus]` [source: dev.to multi-agent orchestration — https://dev.to/focused_dot_io/multi-agent-orchestration-in-langgraph-supervisor-vs-swarm-tradeoffs-and-architecture-1b7e]

---

## 3. Retrieval & Grounding Evidence

The reference doc establishes that RAG-over-ATT&CK reduces hallucination. New 2024–2026 sources strengthen and qualify this.

- **TechniqueRAG** (Lekssays et al., 2025) is the current SOTA pattern for CTI→ATT&CK mapping: off-the-shelf retrievers + an **LLM-based re-ranker** + a **fine-tuned generator**, indexing all techniques uniformly (flat RAG). Reports outperforming zero-shot LLMs and naive RAG on technique annotation. *(We could not extract the exact F1 table from the PDF; treat magnitude as unverified.)* `[SELF-REPORTED; exact metrics unverified]` [source: arXiv:2505.11988 — https://arxiv.org/pdf/2505.11988]
- **Hierarchical ATT&CK RAG** — hierarchical retrieval for adversarial-technique annotation, addressing the ~600+ technique cardinality problem that flat retrieval struggles with. `[SELF-REPORTED]` [source: arXiv:2604.14166 — https://arxiv.org/html/2604.14166]
- **Knowledge-graph RAG (GraphCyRAG / CTI-Thinker / GraphRAG engines)** — Neo4j graphs linking **CVE→CWE→CAPEC→ATT&CK** for interconnected retrieval and tactical-level inference. Consistent with the reference doc's CyberLLM-FINDS finding (KG+GNN retrieval 8.00 vs naive RAG 7.87). `[SELF-REPORTED]` [source: CTI-Thinker, Springer Cybersecurity 2025 — https://link.springer.com/article/10.1186/s42400-025-00505-y; GraphCyRAG — https://anshsrivastava.com/projects/cyber_kg/index.html]
- **RAGIntel / PNNL RAG report** — hybrid retrieval (rerank + compression) over structured ATT&CK to improve accuracy and cut hallucination. `[SELF-REPORTED / TECH REPORT]` [source: PNNL-36792 — https://www.pnnl.gov/main/publications/external/technical_reports/PNNL-36792.pdf; PeerJ CS-3371 — https://peerj.com/articles/cs-3371/]

**Grounding caveat (attribution).** Even *with* multi-agent RAG, attribution stays error-prone at the actor level. AURA's best group-wise result over 150+ ATT&CK groups was **gpt-4o 63.33% top-1 / 73.33% top-2** (Claude 3.5 Sonnet 53.33% / 66.67%); coarse *nation-wise* attribution was far higher (Claude 3.5 Sonnet 83.33% top-1 / 100% top-2; gpt-4o 86.67% / 93.33%). Implication: fine-grained attribution must be presented as **confidence-weighted hypotheses**, never fact. `[SELF-REPORTED]` [source: AURA, arXiv:2506.10175 — https://arxiv.org/abs/2506.10175]

**Net:** grounding via RAG/KG is the single most-validated lever for reducing fabricated technique IDs and is a prerequisite for D2/D4/D5. The enforceable invariant — *technique IDs must resolve to retrieved ATT&CK objects* — is supported across all these systems.

---

## 4. Verification & Human-in-the-Loop Evidence

### How analysts actually use LLMs (the strongest HITL evidence)
A **longitudinal empirical SOC study** (Anneser et al., 2025) analyzed **3,090 queries from 45 analysts over 10 months** in a production enterprise SOC on a GPT-4 deployment:
- Usage was dominated by **command interpretation (31%)**, **text editing/generation (22%)**, and **code/script analysis (11%)**.
- **Only 4% of queries asked for binary malicious/benign judgments.** Analysts used the LLM for "sensemaking and context-building, *rather than for making high-stakes determinations*," preserving their own decision authority.
- Recommendation: a **machine-in-the-loop** posture — *"surface evidence, not recommendations"* — presenting logs and ATT&CK linkages "while omitting prescriptive labels."
`[PRIMARY — empirical field study]` [source: "LLMs in the SOC," arXiv:2508.18947 — https://arxiv.org/html/2508.18947v1]

> Debate-relevant reading: this is direct field evidence that the *valuable* product is evidence-surfacing decision-support, and that practitioners already withhold final judgment from the model. It supports a "copilot, human-gated" thesis — and complicates any "high-autonomy platform" thesis.

### Verification beats self-reflection
- MAST's central prescription is **verification mechanisms** (independent checking), echoing the reference doc's self-critique-paradox warning (arXiv:2310.01798: intrinsic self-correction "can sometimes impair" models; works mainly with external feedback/tools/KB). `[PRIMARY]` [source: arXiv:2503.13657]
- CORTEX operationalizes independent verification: a dedicated reasoning agent synthesizes *evidence gathered by other agents* into an auditable decision, rather than one agent self-grading. `[SELF-REPORTED]` [source: arXiv:2510.00311]

### LangGraph HITL mechanics (production specifics)
- `interrupt()` saves state via the persistence layer and **waits indefinitely** for `Command(resume=...)`; requires a **durable checkpointer** (PostgresSaver/SqliteSaver in prod, not MemorySaver) and a `thread_id`. Persistence is what enables HITL review, replay, resume-after-failure, and time-travel. `[PRIMARY — official docs]` [source: LangChain docs, Interrupts — https://docs.langchain.com/oss/python/langgraph/interrupts]
- Caveat raised by practitioners: checkpoints are **not full durable execution** — long-running, exactly-once, side-effecting workflows may need an external durable-execution layer (e.g., DynamoDB-backed or a workflow engine). This matters for D5, whose hunts run for days. `[WEAK/CONTESTED — vendor blogs with competing interests]` [source: Diagrid — https://www.diagrid.io/blog/checkpoints-are-not-durable-execution-why-langgraph-crewai-google-adk-and-others-fall-short-for-production-agent-workflows; AWS — https://aws.amazon.com/blogs/database/build-durable-ai-agents-with-langgraph-and-amazon-dynamodb/]

### Tool-use / prompt-injection safety (new, important for any externally-acting agent)
- **OWASP ranks prompt injection (LLM01) the top LLM risk**; the **OWASP Top 10 for Agentic Applications (2026)** (released Dec 2025, 100+ contributors) covers agent-specific risks. Indirect prompt injection — malicious instructions hidden in third-party data the agent ingests (CTI reports, web pages, logs) — can hijack multi-step, tool-calling, multi-agent workflows. `[PRIMARY — OWASP]` [source: OWASP Top 10 for LLM Applications 2025 — https://bsg.tech/blog/owasp-llm-top-10/; OWASP Agentic — https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/]
- Recommended defenses: **least-privilege tooling, input/output filtering, human approval for high-risk actions, adversarial testing.** Directly reinforces the reference doc's "human interrupt before any externally-executed query." A threat-hunting agent that ingests adversary-controlled artifacts (the literal job) is an indirect-injection target — a non-obvious but central safety argument. `[PRIMARY]` [source: secops.group — https://secops.group/blog/securing-agentic-ai-the-owasp-top-10-and-beyond/; arXiv:2510.23883 Agentic AI Security — https://arxiv.org/pdf/2510.23883]

---

## 5. Benchmark Reality / Autonomy Ceilings

The reference doc's headline caveat (Cyber Defense Benchmark: no model met ≥50% recall per tactic) is corroborated and extended by a broader benchmark landscape.

- **Cyber Defense Benchmark** (Simbian Research Lab) wraps **106 real attack procedures** from the OTRF Security-Datasets corpus spanning **86 ATT&CK sub-techniques across 12 tactics**; passing bar = ≥50% recall on every tactic. Tested 11 frontier models across 884 runs; **none passed**; best model averaged ~0.46 coverage and flagged only ~3.8–4.5% of malicious events at ~$17.98/run. `[PRIMARY — independent benchmark]` [source: Cyber Defense Benchmark, arXiv:2604.19533; ResearchGate — https://www.researchgate.net/publication/404058784_Cyber_Defense_Benchmark_Agentic_Threat_Hunting_Evaluation_for_LLMs_in_SecOps]
- **DefenderBench** — toolkit for evaluating language agents across cybersecurity *defense* environments (intrusion detection, response). `[PRIMARY — benchmark]` [source: arXiv:2506.00739 — https://arxiv.org/pdf/2506.00739]
- **Guided reasoning beats self-guided reasoning by a wide margin (key feasibility result).** Constraining an LLM pentest agent with a **deterministic ATT&CK-derived task tree** completed 71.8% / 72.8% / 78.6% of subtasks (Llama-3-8B / Gemini-1.5 / GPT-4) vs. a self-guided SOTA baseline at 13.5% / 16.5% / 75.7%, while using **86–206% fewer resources**. This is the strongest single piece of evidence that **deterministic framework scaffolding dramatically outperforms free-form agent reasoning** on weaker/cheaper models and is cheaper on all. `[SELF-REPORTED but large effect; offense-side proxy for defense-side chaining]` [source: arXiv:2509.07939 — https://arxiv.org/abs/2509.07939]
- **Offensive benchmarks rising fast (context, not endorsement):** NYU CTF Bench, CyBench (40 pro CTF tasks), CyberGym (1,507 vulns; 30% single-trial success; 35 zero-days found), CyberExplorer. These show *offensive* capability climbing steeply — relevant because (a) red-team/critic nodes can borrow these methods and (b) the offense/defense asymmetry warns against over-trusting defensive autonomy. `[PRIMARY — benchmarks]` [source: CyberGym discussion / CyberExplorer, arXiv:2602.08023 — https://arxiv.org/html/2602.08023v1; CyBench/NYU CTF Bench surveys]

**Autonomy ceiling summary:** open-ended *autonomous hunting* fails today (Cyber Defense Benchmark). **Constrained, well-bounded tasks** (STRIDE classification, attack-tree decomposition, technique mapping, framework-guided chaining) are where current models are usable — and where deterministic scaffolding closes most of the gap. This asymmetry is the empirical crux of the debate.

---

## 6. Open Problems

1. **No ground truth for completeness.** Threat models and attack trees have no canonical "complete" answer; experts legitimately differ on asset granularity. Evaluate via coverage/comparative metrics, keep humans pruning. `[PRIMARY — acknowledged across literature]`
2. **Self-reported dominance.** AURA, DefenseWeaver, CORTEX, TechniqueRAG, ASTRIDE, Policy-Guided Threat Hunting all report single-paper results on custom/small sets. Architectural shapes are reusable; performance numbers are not independently validated. `[SELF-REPORTED]`
3. **Verification is the bottleneck, not generation.** MAST locates failures disproportionately in verification and coordination; the open problem is a *reliable, measured* critic whose false-confirmation rate is known — and the self-critique paradox means naive self-reflection can make things worse. `[PRIMARY]`
4. **Durable execution vs. checkpointing** for long-lived hunts (days-long D5 loops) is unsettled; checkpointers may be insufficient for exactly-once side-effecting actions. `[WEAK/CONTESTED]`
5. **Indirect prompt injection** is an unsolved, design-defining risk for *any* agent ingesting adversary-controlled data — which is the entire premise of threat hunting and CTI analysis. `[PRIMARY]`
6. **Attribution accuracy ceiling** (~63% top-1 fine-grained) blocks autonomous actor attribution; confidence-weighting is mandatory. `[SELF-REPORTED]`
7. **Cost/latency of multi-agent topologies** is real and measured (supervisor token overhead; ~$18/run on the defense benchmark for poor results) — feasibility is not just accuracy. `[PRIMARY]`

---

## Source index (primary first)
- LangChain, Benchmarking Multi-Agent Architectures — https://www.langchain.com/blog/benchmarking-multi-agent-architectures
- Why Do Multi-Agent LLM Systems Fail? (MAST), arXiv:2503.13657 — https://arxiv.org/pdf/2503.13657
- LLMs in the SOC (empirical field study), arXiv:2508.18947 — https://arxiv.org/html/2508.18947v1
- Guided Reasoning in LLM-Driven Pentesting (ATT&CK task tree), arXiv:2509.07939 — https://arxiv.org/abs/2509.07939
- Cyber Defense Benchmark, arXiv:2604.19533 — https://www.researchgate.net/publication/404058784_Cyber_Defense_Benchmark_Agentic_Threat_Hunting_Evaluation_for_LLMs_in_SecOps
- LangChain docs, Interrupts — https://docs.langchain.com/oss/python/langgraph/interrupts
- OWASP Top 10 for LLM/Agentic Applications — https://bsg.tech/blog/owasp-llm-top-10/ ; https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/
- AURA, arXiv:2506.10175 — https://arxiv.org/abs/2506.10175
- DefenseWeaver, arXiv:2504.18083 (NDSS) — https://arxiv.org/html/2504.18083v1
- CORTEX, arXiv:2510.00311 — https://arxiv.org/abs/2510.00311
- Policy-Guided Threat Hunting, arXiv:2603.23966 — https://arxiv.org/html/2603.23966v1
- TechniqueRAG, arXiv:2505.11988 — https://arxiv.org/pdf/2505.11988
- Hierarchical ATT&CK RAG, arXiv:2604.14166 — https://arxiv.org/html/2604.14166
- CTI-Thinker (KG construction), Springer Cybersecurity 2025 — https://link.springer.com/article/10.1186/s42400-025-00505-y
- ASTRIDE, arXiv:2512.04785 — https://arxiv.org/html/2512.04785
- STRIDE-AI, arXiv:2605.17163 — https://arxiv.org/html/2605.17163v1
- DefenderBench, arXiv:2506.00739 — https://arxiv.org/pdf/2506.00739
- Agentic AI Security survey, arXiv:2510.23883 — https://arxiv.org/pdf/2510.23883
