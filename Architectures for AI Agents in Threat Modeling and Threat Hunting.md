# Reference Architectures for AI Agent Workflows in Threat Modeling and Threat Hunting

## TL;DR
- **Five framework-anchored agent designs are well-grounded enough to recommend**: (1) a STRIDE/PASTA structured-threat-modeling pipeline, (2) a kill-chain/ATT&CK attack-chain constructor, (3) a recursive attack-tree generator, (4) a threat-scenario generator anchored on the Diamond Model and ATT&CK groups, and (5) a hypothesis-driven hunting loop anchored on TaHiTI/PEAK/Sqrrl. All five map cleanly onto LangGraph's StateGraph, conditional edges, checkpointer-backed persistence, and human-in-the-loop interrupts.
- **The single most important design principle is "constrain generation with structured frameworks plus retrieval, then verify with a separate critic and a human."** Evidence shows unconstrained LLM agents fail dramatically at open-ended hunting — on the independent Cyber Defense Benchmark (arXiv:2604.19533), the best model (Claude Opus 4.6) submitted correct flags for only 3.8% of malicious events on average — while ATT&CK-task-tree-guided reasoning and RAG over ATT&CK measurably reduce hallucination. The frameworks supply the deterministic scaffolding the LLM cannot reliably invent.
- **Topology should escalate with task ambiguity**: deterministic graph/orchestrator-worker pipelines for STRIDE, PASTA and attack-tree work; supervisor multi-agent for hunting and scenario generation; reserve swarm for nothing here. Always pair a generator with a red-team/critic node and place human interrupts before any externally-executed query.

## Key Findings

1. **Frameworks provide the control flow; the LLM provides the content.** Every established method here is already a state machine — PASTA's seven stages, the Sqrrl four-stage loop, PEAK's Prepare-Execute-Act, the kill chain's seven phases, the Diamond Model's event→thread→group hierarchy. These map almost one-to-one onto LangGraph nodes and edges. This is the strongest, least speculative part of the synthesis.

2. **Retrieval grounding is essential and empirically validated.** RAG over the ATT&CK STIX knowledge base and CTI corpora measurably improves technique annotation and reduces hallucination (TechniqueRAG, RAGIntel, hierarchical ATT&CK RAG). In a 5-dimension LLM-judge comparison on MITRE ATT&CK queries (CyberLLM-FINDS 2025, arXiv:2601.06779), a knowledge-graph + GNN retrieval pipeline scored highest overall (8.00, with Accuracy 8.2 and Specificity 7.9) versus pure RAG (avg 7.87) — i.e., structuring retrieval around the CVE→CWE→CAPEC→ATT&CK graph improves accuracy and specificity over naive RAG.

3. **Self-critique helps where the base model is weak and hurts where it is strong.** Reflection/Reflexion patterns reduce hallucination on hard tasks but can *induce* errors on tasks the model already handles well (the "self-critique paradox"). Google DeepMind & UIUC ("Large Language Models Cannot Self-Correct Reasoning Yet," arXiv:2310.01798) found that intrinsic self-correction without external feedback "can sometimes impair the performance of these models" and typically succeeds "only when they can leverage external sources, such as human feedback, an external tool... or a knowledge base." This argues for an *independent*, externally-grounded critic and human checkpoints rather than pure self-reflection in a security context.

4. **Current LLM agents are not trustworthy as autonomous hunters.** On the Cyber Defense Benchmark, Simbian Research Lab tested 11 frontier models across 884 runs and 105 attack procedures against a passing bar of "≥50% recall on every tested MITRE ATT&CK tactic"; "Not one passed." The best model (Claude Opus 4.6) averaged 0.46 coverage and found only ~4.5% of flags at $17.98/run. This is the central caveat: these designs are decision-support and drafting aids with mandatory human verification, not autonomous systems.

5. **Multi-agent role decomposition is already demonstrated in the literature** (AURA for attribution; DefenseWeaver for TARA/attack trees), giving concrete, citable role names to anchor designs rather than inventing roles.

## Details

### A. Established framework facts (high confidence)

**MITRE ATT&CK and tooling.** ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs). The canonical machine-readable form is STIX 2.0/2.1, served via the MITRE TAXII server and the `attack-stix-data` GitHub repo; the `attackcti` and `mitreattack-python` libraries (and the `stix2`/`taxii2client` libraries) parse it. ATT&CK objects include attack-patterns (techniques), intrusion-sets (groups), malware, tools, course-of-action (mitigations), data sources/components, and `uses` relationships connecting groups→techniques. ATT&CK Navigator layers are JSON files that annotate the matrix for coverage visualization. MITRE's CTID built TRAM, which uses a fine-tuned SciBERT/LLM to map CTI report sentences to ATT&CK techniques; per CTID's Jon Baker, the LLM "identified the correct ATT&CK technique 88 of 100 times and missed finding 12 techniques out of 100 samples" for the ~50 most prevalent techniques it covers, and CTID notes that mapping to the full ~600+ (sub-)techniques is the hard, unsolved part.

**STRIDE.** Microsoft's six-category threat taxonomy (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege), typically applied per-element over a data-flow diagram (DFD). Often paired with DREAD for risk scoring.

**PASTA (Process for Attack Simulation and Threat Analysis).** A seven-stage risk-centric methodology (UcedaVelez & Morana, 2015): (1) define business objectives; (2) define technical scope; (3) application decomposition (DFDs, trust boundaries, asset list); (4) threat analysis (threat agents, attack vectors); (5) vulnerability analysis (CVSS scoring); (6) attack modeling/simulation (produces attack trees and attack paths); (7) risk and impact analysis (risk profile, countermeasures). Each stage feeds the next.

**Attack trees (Schneier, 1999).** Labeled acyclic trees: root = attacker goal; children = refinements; leaves = atomic attack components. Refinement nodes are **AND** (all children needed) and **OR** (any child suffices); later work adds SAND (sequential-AND). Leaf values (e.g., cost, possible/impossible) propagate to the root (OR = min/any; AND = sum/all). Reusable across systems.

**Lockheed Martin Cyber Kill Chain.** Seven ordered phases (reconnaissance, weaponization, delivery, exploitation, installation, command & control, actions on objectives) modeling intrusions as phased progressions rather than single events.

**Diamond Model of Intrusion Analysis (Caltagirone, Pendergast, Betz, 2013).** The atomic element is the **event**, composed of four core features — **adversary, capability, infrastructure, victim** — arranged as a vertex-labeled undirected graph (diamond). Verbatim: *"For every intrusion event there exists an adversary taking a step towards an intended goal by using a capability over infrastructure against a victim to produce a result"* (Axiom 1). Meta-features include timestamp, phase, result, direction, methodology, resources, each core feature carrying an independent confidence value. **Pivoting**: *"By pivoting across edges and within vertices, analysts expose more information about adversary operations and discover new capabilities, infrastructure, and victims."* Events are phase-ordered by adversary-victim pair into **activity threads**, then coalesced into **activity groups/campaigns**. The model is explicitly complementary to the Kill Chain — it ingests any phased model via the phase meta-feature (Axiom 4: "Every malicious activity contains two or more phases which must be successfully executed in succession to achieve the desired result").

**Threat-hunting methodologies.**
- **Sqrrl Threat Hunting Loop** (2015, the first influential framework): four stages — (1) create hypothesis, (2) investigate via tools and techniques, (3) uncover new patterns/TTPs, (4) inform & enrich analytics (automate) — iterated continuously. Accompanied by the Hunting Maturity Model (HMM0–HMM4) and the Pyramid of Pain (Bianco).
- **TaHiTI** (Targeted Hunting Integrating Threat Intelligence; Dutch financial sector / FI-ISAC NL / Betaalvereniging Nederland, 2018): three phases — Initiate (trigger → abstract → hunting backlog), Hunt (define/refine hypothesis, execute investigation, with threat-intel-driven *pivoting*), Finalize (document, hand off, feed detections). Hypotheses are intelligence-driven; results feed back to CTI. Supported by the "MaGMa for threat hunting" tool.
- **PEAK** (Prepare, Execute, and Act with Knowledge; Splunk SURGe — David Bianco, Ryan Fetterman, Sydney Marrone, 2023): three hunt types (Hypothesis-Driven, Baseline/Exploratory Data Analysis, Model-Assisted Threat Hunting/M-ATH) and the **ABLE** framework for capturing a hypothesis (Actor, Behavior, Location, Evidence).
- **MITRE TTP-Based Hunting** (Daszczyszak, Ellis, Luke, Whitley; for USCYBERCOM): a "V" methodology that uses ATT&CK TTPs plus the Cyber Analytic Repository (CAR) data model to describe adversary actions in terms of the data required to detect them, irrespective of tool/product, producing prioritized analytics (heat-map coverage).

### B. Established AI-agent / LangGraph design patterns (high confidence)

**LangGraph primitives.** `StateGraph` with typed state (TypedDict/Pydantic); **nodes** = functions/runnables; **edges** and **conditional edges** (routing functions) define control flow; **reducers** (e.g., `operator.add`, `add_messages`) merge state updates; the **Send API** enables dynamic fan-out (map-reduce/orchestrator-worker); **ToolNode** executes tool calls; **checkpointers** (MemorySaver for dev; SqliteSaver/PostgresSaver for production) persist a StateSnapshot at every super-step keyed by `thread_id`, enabling pause/resume, time-travel, and replay; the **Store** interface holds long-term cross-thread memory via namespaces.

**Human-in-the-loop.** The `interrupt()` function pauses a node, persists state, and waits indefinitely for `Command(resume=...)`. Critical engineering constraints: a durable checkpointer is required; code *before* `interrupt()` re-executes on resume and must be idempotent (side effects after the interrupt); never wrap `interrupt()` in try/except. `interrupt_before`/`interrupt_after` provide static breakpoints. This is the mechanism for analyst approval of generated queries, hypotheses, and reports.

**Multi-agent topologies.**
- **Supervisor**: a central coordinator classifies and routes to specialist agents; control returns to the supervisor after each. More accurate routing, clearer traces, easier debugging; extra token/latency cost per hop. LangChain now recommends the tool-calling supervisor pattern over the older library for most cases.
- **Hierarchical**: supervisors-of-supervisors (nested), for larger role trees.
- **Swarm**: decentralized peer-to-peer handoffs via `Command(goto=..., graph=Command.PARENT)`; faster, fewer LLM calls, but harder to reason about and prone to long handoff chains. General guidance: start with supervisor; graduate to swarm only when latency is the proven bottleneck.
- **Orchestrator-worker**: planner decomposes a task, dispatches workers via Send (dynamic fan-out), synthesizer merges. Ideal when subtasks are independent and the count is runtime-dependent.
- **ReAct/tool loop**: single agent with `should_continue` conditional edge looping between an LLM node and a ToolNode.

**Verification patterns.** Reflection (Self-Refine) and Reflexion (Actor/Evaluator/Self-Reflection) implement generate→critique→refine loops. Evidence is mixed: self-critique reduces hallucination on hard tasks but can introduce errors on tasks the model already handles well (the "self-critique paradox"; arXiv:2310.01798). External verification (tools, retrieval cross-checking) and an *independent* critic model are more reliable than pure self-reflection. **LLM-as-a-judge** (e.g., G-Eval) with Likert scales is the common automatic evaluation method, complemented by expert human evaluation.

**Concrete named role decompositions from the literature** (self-reported single-paper results; treat performance as claims):
- **AURA** (Rani & Shukla, IIT Kanpur, arXiv:2506.10175): multi-agent RAG for APT attribution built on LangChain + Qdrant + GPT-4o. Roles: preprocessing/metadata extraction → **Query Rewriting Agent** (resolves ambiguous references like "they" to explicit actor names such as APT28 or Lazarus Group) → **Semantic Retriever Agent** (vector retrieval over CTI corpus) → **Decision Agent** (judges context relevance; routes to web search if irrelevant) → **Web Search module** → **Attribution Generation Agent** (predicts actor + natural-language justification) → **Conversational Memory module**. For group-wise attribution over 150+ MITRE ATT&CK groups, "gpt-4o achieved the highest top-1 accuracy at 63.33% and top-2 accuracy at 73.33%" on a 30-report held-out set (Claude 3.5 Sonnet: 53.33% top-1 / 66.67% top-2).
- **DefenseWeaver** (Yang et al., arXiv:2504.18083): multi-agent function-level TARA generating attack trees. Roles: **Sub-Tree Constructor** (builds sub-trees per atomic node with explicit AND/OR logic), **Attack-Tree Assembler** (merges sub-trees into a coherent tree, enforcing logical consistency between consecutive nodes), **Risk Assessor** (attack-feasibility + impact assessment, ISO/SAE 21434-aligned). Uses Chain-of-Thought to structure sub-tree construction; reports 8,200+ generated attack trees in production integrations.

### C. The five recommended designs (the synthesis)

For each: task → framework(s) operationalized → topology & roles → LangGraph mapping → tools/RAG → verification/HITL → confidence.

---

#### Design 1 — Structured Threat Modeling over a system/DFD (STRIDE + PASTA)

- **Task**: Given a system description or DFD, enumerate threats per element and produce prioritized, mitigated threats.
- **Frameworks**: STRIDE (per-element categorization) executed inside the PASTA stage skeleton (decomposition → threat analysis → vulnerability → attack modeling → risk).
- **Topology**: Deterministic **orchestrator-worker** pipeline, not a free-form multi-agent system. The PASTA stages are fixed nodes; per-element STRIDE analysis is a Send-based fan-out (one worker per DFD element/trust boundary), then a synthesizer aggregates.
- **Roles**: Planner/decomposer (parses DFD into elements, trust boundaries, data flows) → STRIDE-analyst workers (one per element) → vulnerability-mapper (CVE/CVSS, optionally CWE→CAPEC→ATT&CK via KG) → risk-scorer (DREAD/CVSS) → critic (coverage check: did every element get all six STRIDE categories considered?) → reporter.
- **LangGraph**: `StateGraph` with state = {dfd_elements, threats[], vulnerabilities[], risks[], report}; reducer `operator.add` on `threats`; `assign_workers` conditional edge issues `Send("stride_worker", {element})` per element; synthesizer node; a coverage-critic node with a conditional edge that loops back to re-run workers on uncovered elements; final `interrupt()` for analyst sign-off.
- **Tools/RAG**: RAG over an internal threat catalog and CWE/CAPEC; optional ATT&CK mapping for technique context. Prior art: ThreatModeling-LLM (banking/STRIDE+NIST 800-53), ThreatCompute (Kubernetes attack graphs + ATT&CK), ASTRIDE (DFD-driven, VLM+reasoning-LLM).
- **Verification/HITL**: Structured output schemas per element prevent parsing errors; the coverage critic enforces the STRIDE matrix is fully populated; human approves the final threat list. Because STRIDE per-element is a well-bounded classification task, an independent critic is more valuable than self-reflection.
- **Confidence: HIGH.** The framework is a deterministic checklist; the LLM's job (classification + drafting) is exactly where it is strongest, and STRIDE classification by LLMs is studied (e.g., 5G STRIDE case study, arXiv:2505.04101). The orchestrator-worker mapping is a documented LangGraph pattern.

---

#### Design 2 — Attack-Chain Construction (Cyber Kill Chain + ATT&CK technique chaining)

- **Task**: From a CTI report, alert cluster, or scenario, construct an ordered chain of ATT&CK techniques across kill-chain phases.
- **Frameworks**: Kill Chain (phase ordering) + ATT&CK (technique vocabulary) + Diamond activity-thread concept (phase-ordered events per adversary-victim pair).
- **Topology**: **Supervisor multi-agent** OR a guided single agent constrained by a deterministic ATT&CK task tree. Strong evidence favors constraining the LLM with a pre-built ATT&CK/kill-chain task tree to prevent hallucinated/cyclical steps (Guided Reasoning in LLM-Driven Penetration Testing, arXiv:2509.07939).
- **Roles**: Supervisor → TTP-extractor/ATT&CK-mapper (TRAM-style; RAG-backed) → phase-sequencer (orders techniques into kill-chain phases / activity thread) → critic/red-team (checks technique pre/post-conditions chain logically) → reporter (emits ATT&CK Navigator layer JSON).
- **LangGraph**: Supervisor as router node with conditional edges to specialist nodes; state carries {techniques[], phase_order[], navigator_layer}; the ATT&CK task tree is encoded as allowed transitions in the sequencer node's logic (deterministic guardrail); ToolNode wraps the ATT&CK STIX/`attackcti` query tool and a Navigator-layer emitter.
- **Tools/RAG**: ATT&CK STIX/TAXII via `attackcti`/`mitreattack-python`; RAG over ATT&CK technique descriptions and `uses` relationships; Navigator layer export. Prior art: RAG-augmented attack-graph generation by CVE chaining (arXiv:2408.05855); KillChainGraph (phase-mapped ATT&CK, arXiv:2508.18230); MM-AttacKG.
- **Verification/HITL**: The critic verifies each technique's preconditions are satisfied by an earlier technique's effects (chain validity); RAG grounds technique IDs to real ATT&CK objects (prevents fabricated technique IDs); human reviews the chain. Constrain technique IDs to the retrieved ATT&CK set — never accept a free-text technique ID the retriever did not return.
- **Confidence: HIGH for the mapping/sequencing-with-guardrails design; MEDIUM for fully autonomous chaining.** ATT&CK mapping and kill-chain phase assignment are demonstrated; unconstrained multi-step chaining is where hallucination appears, hence the deterministic task-tree guardrail.

---

#### Design 3 — Attack-Tree Generation and Refinement (Schneier + PASTA stage 6)

- **Task**: Given a root attacker goal, recursively generate an AND/OR attack tree with refinements down to atomic leaves, then refine/score.
- **Frameworks**: Schneier attack trees (AND/OR/SAND refinement) as PASTA stage 6 output.
- **Topology**: **Orchestrator-worker with recursion**, mirroring the demonstrated DefenseWeaver decomposition.
- **Roles** (anchored on DefenseWeaver's named roles): **Sub-Tree Constructor** (expands a node into children with explicit AND/OR logic) → **Attack-Tree Assembler** (merges sub-trees, enforces logical consistency between consecutive nodes) → **Risk Assessor** (feasibility + impact per leaf, propagated to root) → critic (checks refinement validity: are AND-children jointly sufficient? are OR-children genuinely alternative?).
- **LangGraph**: Recursive expansion via Send fan-out per frontier node; state = {tree (adjacency list), open_nodes[], leaf_values}; a conditional edge checks whether any node still needs refinement (loops) or all are atomic (proceeds to assembler); reducers merge sub-trees; recursion-limit guard prevents runaway depth; `interrupt()` lets the analyst prune/approve branches mid-expansion (time-travel/`update_state` supports editing the tree and re-running).
- **Tools/RAG**: RAG over ATT&CK (to populate realistic leaf techniques) and CVE/CAPEC; CVSS for leaf feasibility. Prior art: DefenseWeaver (arXiv:2504.18083); automated attack-tree generation with optimal shape/labelling (arXiv:2311.13331); attack-tree generation via process mining (arXiv:2402.12040).
- **Verification/HITL**: Independent critic validates refinement semantics; human prunes the combinatorial explosion (attack trees grow exponentially — human-in-the-loop pruning is a feature, not a fallback). Value propagation (AND=sum, OR=min) is deterministic and computed in code, not by the LLM.
- **Confidence: HIGH for structure/decomposition (directly demonstrated by DefenseWeaver); MEDIUM for leaf-completeness** (no ground truth for "all" attacks; coverage is inherently open — see open problems).

---

#### Design 4 — Threat-Scenario Generation (Diamond Model + ATT&CK groups)

- **Task**: Generate plausible, intelligence-grounded threat scenarios (who, using what capability, over what infrastructure, against which asset, in what phase order).
- **Frameworks**: Diamond Model (event = adversary/capability/infrastructure/victim; pivoting; activity threads) + ATT&CK group/technique `uses` relationships + kill-chain phasing.
- **Topology**: **Supervisor multi-agent** with a pivoting loop.
- **Roles**: Supervisor → adversary/group-profiler (retrieves ATT&CK intrusion-set + its known techniques) → capability/infrastructure mapper (Diamond pivoting across edges) → scenario-composer (assembles phase-ordered activity thread) → red-team critic (plausibility: does this group actually use these TTPs? is the infrastructure consistent?) → reporter.
- **LangGraph**: Supervisor router; state = {diamond_events[], activity_thread[], scenario}; pivoting implemented as a conditional-edge loop that fills empty Diamond features by querying ATT&CK relationships until features are populated or marked as knowledge gaps; ToolNode wraps `attackcti` group/technique/software queries; checkpointer enables iterative refinement.
- **Tools/RAG**: ATT&CK STIX (`uses` relationships group→technique, software→technique); RAG over CTI reports for capability/infrastructure detail; optional knowledge graph (CVE→CWE→CAPEC→ATT&CK).
- **Verification/HITL**: Critic grounds every claimed group→technique edge to a real ATT&CK relationship (no invented attributions); analyst approves scenario realism. Attribution is error-prone (AURA's best group-level result was 63.33% top-1 / 73.33% top-2) — present scenarios as hypotheses with confidence values (Diamond core features each carry independent confidence), never as fact.
- **Confidence: MEDIUM-HIGH.** The Diamond/ATT&CK grounding is solid and the pivoting-as-graph-traversal mapping is natural; the speculative element is the realism of *generated* (vs. observed) adversary behavior, which must stay human-gated.

---

#### Design 5 — Hypothesis-Driven Threat Hunting (TaHiTI / PEAK / Sqrrl loop + TTP-based hunting)

- **Task**: Generate hunting hypotheses, translate to queries, test against data, refine iteratively, and feed back detections.
- **Frameworks**: Sqrrl four-stage loop (or TaHiTI Initiate-Hunt-Finalize) as the master control loop; PEAK's ABLE (Actor, Behavior, Location, Evidence) to structure each hypothesis; MITRE TTP-based hunting + CAR data model to tie behaviors to required data sources; ATT&CK for the behavior vocabulary.
- **Topology**: **Supervisor multi-agent wrapped in a cyclic StateGraph** (the hunting loop). This is the most agentic of the five because hunting is genuinely iterative and exploratory.
- **Roles**: Supervisor/loop-controller → trigger/intel agent (ingests CTI, proposes trailheads) → hypothesis-generator (emits ABLE-structured hypotheses, RAG-grounded in ATT&CK + threat intel) → query-generator (translates Behavior+Location+Evidence into SIEM/EDR queries / Sigma rules, using CAR data model to pick data sources) → investigator/executor (runs queries via ToolNode, summarizes evidence) → critic/evaluator (does evidence confirm/deny? what is the next pivot?) → detection-engineer (converts confirmed hunts to detections) → reporter (documents per PEAK "Act" / TaHiTI "Finalize").
- **LangGraph**: Cyclic graph realizing the loop: hypothesis → query → investigate → evaluate → (conditional edge: refine hypothesis / pivot / conclude). State = {hypotheses[], queries[], evidence[], findings[], detections[]} with reducers accumulating evidence; checkpointer/`thread_id` persists the hunt across long pauses (hunts run for days); Store holds cross-hunt memory (prior hypotheses, baselines); **mandatory `interrupt()` before query execution** against production data, and before promoting a detection.
- **Tools/RAG**: SIEM/EDR query generation (e.g., SPL); Sigma rule generation; ATT&CK STIX; CTI feeds; CAR data model for data-source selection. Prior art: Policy-Guided Threat Hunting (Agentic AI + Splunk SOC triage, arXiv:2603.23966); Cyber Defense Benchmark (evaluation, arXiv:2604.19533).
- **Verification/HITL**: Independent critic evaluates evidence sufficiency; **human approval gate before any query runs and before any detection is deployed**; RAG grounds hypotheses to real TTPs. The self-critique paradox argues for a separate evaluator model plus human, not self-reflection alone.
- **Confidence: MEDIUM for design soundness, LOW for autonomy.** The loop maps perfectly to a cyclic LangGraph and the frameworks are authoritative, BUT independent benchmarking shows current LLMs fail badly at open-ended hunting (no model passed the ≥50%-recall-per-tactic bar on the Cyber Defense Benchmark) — so this design is a hunter's *copilot* (drafting hypotheses and queries, summarizing evidence) with the human firmly in the loop, not an autonomous hunter.

### D. Cross-design comparison

| Design | Framework spine | Topology | Key LangGraph primitive | Autonomy ceiling | Confidence |
|---|---|---|---|---|---|
| 1. STRIDE/PASTA threat modeling | STRIDE + PASTA | Orchestrator-worker (deterministic) | Send fan-out per DFD element | Draft + human review | HIGH |
| 2. Attack-chain construction | Kill Chain + ATT&CK | Supervisor / guided single-agent | Conditional edges + ATT&CK task-tree guardrail | Assisted mapping | HIGH (guarded) |
| 3. Attack-tree generation | Schneier + PASTA-6 | Recursive orchestrator-worker | Recursive Send + recursion limit | Draft + human pruning | HIGH (structure) |
| 4. Threat-scenario generation | Diamond + ATT&CK groups | Supervisor + pivoting loop | Conditional-edge pivot loop | Hypotheses w/ confidence | MED-HIGH |
| 5. Hypothesis-driven hunting | Sqrrl/TaHiTI/PEAK + TTP-hunting | Cyclic supervisor | Checkpointer + interrupt + Store | Copilot only | MED (LOW autonomy) |

**Topology selection rule of thumb**: deterministic pipeline when the framework is itself a checklist (1, 3); supervisor when distinct expert roles and routing are needed (2, 4, 5); avoid swarm entirely — security workflows need auditable, traceable control flow, which the supervisor and explicit-graph patterns provide and swarm sacrifices.

**Shared design invariants across all five**: (i) constrain IDs/techniques to retrieved ATT&CK objects; (ii) separate generator from critic (independent, externally-grounded model), do not rely on self-reflection alone; (iii) human interrupt before any externally-executed action and before publishing; (iv) carry explicit confidence values (Diamond-style) on every generated claim; (v) durable checkpointer + Store for iterative refinement and auditability; (vi) structured-output schemas at every node.

### E. Evaluation approaches (how to assess generated artifacts)

- **LLM-as-a-judge (G-Eval, GPT-4-as-judge)** with 5-point Likert scales on relevance, completeness, accuracy, specificity, clarity — used in AttackSeqBench, ThreatCompute, AURA, CyberRAG. Use an *independent* judge model to avoid self-evaluation bias.
- **Expert human evaluation** on sampled outputs (AttackSeqBench used three cybersecurity experts; human baseline ~0.63 shows the tasks are hard even for humans).
- **Holdout/ground-truth benchmarks**: TRAM (technique-mapping precision/recall/F1); Cyber Defense Benchmark (CTF-style recall against Sigma-derived ground truth — the bar of ≥50% recall per ATT&CK tactic for unsupervised deployment, which no model met); AttackSeqBench (sequence understanding); rule-generation holdout benchmarks for Sigma/detection quality.
- **Coverage metrics**: ATT&CK Navigator heat-map coverage (techniques addressed vs. relevant), tied to *evidence* not just counts; for attack trees, leaf-completeness against expert trees (acknowledging no canonical ground truth).
- **Threat-modeling-specific**: note explicitly that automated threat modeling "lacks a definitive ground truth" — expert models differ on asset granularity — so prefer relative/comparative and coverage metrics over absolute accuracy.

## Recommendations

**Stage 1 — Start with the two highest-confidence, lowest-risk designs.** Build Design 1 (STRIDE/PASTA) and Design 3 (attack trees) first. They are deterministic pipelines where the LLM does bounded classification/drafting, the frameworks supply the control flow, and DefenseWeaver/ThreatModeling-LLM provide validated blueprints. Implement as LangGraph orchestrator-worker graphs with Send fan-out, structured-output schemas, a coverage critic, and a final human interrupt.

**Stage 2 — Add ATT&CK grounding infrastructure before anything hunting-related.** Stand up the retrieval layer: ingest ATT&CK STIX (`attackcti`/`mitreattack-python`), build a vector store of technique descriptions and CTI, and ideally a CVE→CWE→CAPEC→ATT&CK knowledge graph (knowledge-graph + GNN retrieval scored 8.00 vs naive RAG's 7.87 on MITRE queries in CyberLLM-FINDS 2025). Enforce the invariant that all technique IDs must resolve to retrieved ATT&CK objects. This is the prerequisite for Designs 2, 4, and 5.

**Stage 3 — Build Design 2 (attack chains) with the deterministic ATT&CK task-tree guardrail**, then Design 4 (scenarios) with Diamond-pivoting and confidence values. Add an independent critic agent (not self-reflection) and LLM-as-judge evaluation against held-out CTI.

**Stage 4 — Build Design 5 (hunting) last and only as a copilot.** Mandatory human interrupt before query execution and detection deployment; durable Postgres checkpointer; Store for cross-hunt memory. Do not pursue autonomous hunting.

**Benchmarks/thresholds that change the recommendation**:
- *Raise autonomy* for a design only when an independent holdout benchmark shows ≥ the deployment bar (e.g., Cyber Defense Benchmark's ≥50% recall per ATT&CK tactic; TRAM-style F1 on technique mapping) AND the critic's false-confirmation rate is measured and low.
- *If the self-critique loop reduces accuracy* on your held-out set (watch for the self-critique paradox on easy tasks), disable reflection for that task and rely on the independent, externally-grounded critic + human only.
- *If retrieval grounding does not measurably cut fabricated technique IDs*, do not expand to Designs 2/4/5 — fix retrieval first.
- *Trigger to add hierarchical topology*: only when a supervisor manages more than ~5 specialist agents (multi-agent systems become hard to manage past that point).

## Caveats

- **Current LLM agents are unreliable for autonomous, open-ended threat hunting.** On the Cyber Defense Benchmark, 11 frontier models were tested across 884 runs; none met the ≥50%-recall-per-tactic deployment bar, and the best (Claude Opus 4.6) flagged only ~3.8–4.5% of malicious events. All five designs are decision-support/drafting tools requiring human verification; Design 5 especially is a copilot, not an autonomous hunter.
- **Self-reported results dominate the agent literature.** AURA, DefenseWeaver, ThreatModeling-LLM, ThreatCompute, ASTRIDE etc. report single-paper results on small/custom evaluation sets; treat their accuracy figures as claims, not independently validated facts. They are cited here as architectural prior art (role decompositions, pipeline shapes), which is robust, not as performance guarantees.
- **The self-critique paradox is a genuine risk in security.** Critic agents primed to find errors can invent them on outputs that were already correct, flipping right answers to wrong; intrinsic self-correction "can sometimes impair" model performance (arXiv:2310.01798). Use independent, externally-grounded critics and human gates; measure the critic's effect on a held-out set before trusting it.
- **Attack-tree and threat-model coverage have no ground truth.** "Completeness" of generated trees/models is inherently open; expert models legitimately differ. Evaluate via coverage and comparative metrics, and keep humans pruning.
- **Designs deliberately NOT proposed (too speculative):** (a) fully autonomous closed-loop hunt-detect-respond agents that execute remediations without human approval — unsupported by current reliability evidence; (b) swarm topologies for these tasks — they sacrifice the auditability security work requires; (c) agents that *autonomously attribute* attacks to named actors as fact — attribution accuracy is too low (≤~63% top-1) and the stakes too high (present as confidence-weighted hypotheses only); (d) LLM-driven *autonomous* exploitation/attack-path execution — out of scope and operationally inappropriate for a defensive design; (e) RL-trained end-to-end hunting policies — promising in some papers but weakly grounded and opaque, not recommended as a reference design.
- **Framework-vs-synthesis boundary**: The framework facts (§A) and LangGraph primitives (§B) are well-established. The five designs (§C) are a *synthesis* — the individual ingredients (orchestrator-worker, supervisor, RAG-over-ATT&CK, interrupt-based HITL, framework-as-state-machine) are well-trodden, but their specific composition for each threat-modeling/hunting task is novel engineering guidance, not an empirically validated standard. Confidence ratings reflect this.