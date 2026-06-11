# Conclusion — Most Feasible Architecture for AI Agents in Threat Modeling & Threat Hunting

## Verdict

The most feasible architecture is **not** a portfolio of isolated per-task silos, and **not** a unified autonomous multi-agent platform. It is a **deterministic per-task backbone with a grounded, human-gated coordination core** — built incrementally, proving the deployment-evidenced pipelines first and *earning* the cross-task machinery through measurement rather than assuming it.

## The architecture

- **N per-task deterministic graphs** — D1 STRIDE/PASTA, D2 attack-chains, D3 attack-trees, D4 Diamond scenarios, D5 hunting-copilot — each a framework-as-state-machine where the LLM does only bounded classification/drafting inside fixed nodes, each with its **own externally-grounded critic**.
- **Shared substrate (three stores):** (1) a **versioned, read-only** ATT&CK/CVE→CWE→CAPEC→ATT&CK **KG grounding layer** — agents never write it; technique IDs must resolve to retrieved objects; (2) an append-only, **sign-off-gated, provenance-tracked artifact store** (cross-task outputs reused as confidence-weighted hypotheses, never as ground truth); (3) a separate, **offline-curated, confidence-capped "promoted-edges" overlay**. Plus one hardened indirect-injection boundary and one audit/trace schema with deterministic replay (pinned to a KG version) and per-claim confidence.
- **Cross-task coupling:** a single **human-gated tiered dispatcher** (a parent graph over the pipelines as subgraphs) — tier-1 = deterministic KG-frontier retrieval + a grounded re-ranker; tier-2 = a bounded open-generation reasoner only on a genuine no-edge miss (`max re-rank score < τ`); both halt at `interrupt()` with the **human as sole disposer**, the gate surfacing *evidence, not verdicts*.
- **Gate fires only on side-effecting steps** (read-only queries against authorized telemetry don't block).
- **Forbidden:** always-on autonomous supervisor · ungated agent-to-agent collaboration · autonomous hunting (D5 is a copilot only).

## The recommendation

1. **Build D1 (STRIDE/PASTA) and D3 (attack-trees) now** — the only deployment-proven tasks — as independent deterministic LangGraph pipelines on the shared read-only grounding layer, with per-pipeline critics and human sign-off.
2. **Before** building any cross-task coordination, run an **offline spike** on a historical corpus to measure the KG-miss rate (τ-sweep) and re-ranker accuracy. *If the miss-rate is high at sane τ, the tiered design is wrong and a reasoner-first design was right* — this is the falsifiable test.
3. Only if those numbers justify it: add the human-gated tiered dispatcher, then D2/D4, then D5 as a copilot — never autonomous.
4. Treat HITL as **unfalsified, not validated**: pre-register a kill-criterion (if "evidence-not-verdicts" doesn't beat verdict-framing and on-graph false-approval exceeds a set threshold, *lower* autonomy).

## Honest limits (documented, not closed)

- **On-graph misdirection injection** — a poisoned-but-grounding decoy pivot passes any grounding check; no architecture closes it (mitigate via shadow-channel canaries, parallel hypotheses, analyst rotation, measured false-approval rate).
- **Automation bias** survives at both tiers; "evidence-not-verdicts" is an unproven mitigation that must be instrumented.
- **Autonomy ceiling** — no current model passes open-ended hunting (Cyber Defense Benchmark); D5 stays a copilot.
- **Attribution** stays a confidence-weighted hypothesis (~63% top-1).
- **No ground truth** for threat-model/attack-tree completeness — evaluate by coverage and comparison, keep humans pruning.

---
*Full engineering spec: `05_final_architecture.md` (Rev 3). Debate transcript & judging: `03_debate_log.md`. Red-team review: `06_red_team_review.md`.*
