# SecWeave — MVP Alignment Specification

## Product definition

SecWeave is a two-month R&D prototype for continuous AI-assisted security testing. Its technical core is the System Security Context Engine. The MVP is a vertical slice for one open-source web repository using a Python or Node stack, SQLite persistence, Semgrep, Trivy, independent validation, and a developer-ready finding workflow.

## Architecture mapping

| SecWeave layer | Repository implementation |
| --- | --- |
| Scope, policy, approval | `policies/`, `core/scope/`, `core/threat-model/` |
| Ingestion and adapters | `adapters/semgrep/`, `adapters/trivy/`, SARIF, CycloneDX, Git |
| Context store | `core/state/sqlite-store.mjs`, `schemas/` |
| Scheduler and model routing | `core/scheduler/`, `providers/` |
| Discovery lanes | `agents/`, whitebox inventory, deterministic tool tasks |
| Hypothesis store | SQLite `hypotheses` and validation attempts |
| Independent validation | `agents/validator/`, runtime safety boundary |
| Developer workflow | CLI, reports, Agent Kit, MCP boundary |

## Domain model

The durable chain is:

```text
Observation → Fact/Assumption/Invariant → Signal → Hypothesis
→ Validation Attempt → Evidence-backed Finding → Feedback
→ Remediation → Fix Verification
```

Every claim/evidence record carries provenance or source revision. Findings are never promoted from a signal or hypothesis without explicit evidence IDs.

## Finding lifecycle

The state machine supports `SIGNAL`, `HYPOTHESIS`, `UNDER_REVIEW`, `VALIDATION_PLANNED`, `VALIDATION_BLOCKED`, `PARTIALLY_VALIDATED`, `CONFIRMED`, `REJECTED`, `ACCEPTED`, `RISK_ACCEPTED`, `PATCH_PROPOSED`, `FIX_VERIFIED`, `CLOSED`, and `REOPENED`.

## Eight-week delivery plan

1. Baseline, scope, architecture, and persistence.
2. State machine, scheduler, leases, retry, and model routing.
3. Git/whitebox ingestion plus Semgrep and Trivy normalization.
4. Recon and specialist discovery lanes.
5. Independent validation and proof-gap handling.
6. Developer report, feedback, remediation, and Agent/MCP integration.
7. Incremental analysis, cache/cost/latency accounting, and evaluation.
8. OSS demo, benchmark, documentation, runbook, retrospective, and handover.

## Acceptance checklist

- [x] Runnable CLI and embeddable Agent Kit.
- [x] SQLite resume/retry state.
- [x] Semgrep and Trivy normalized signal contracts.
- [x] At least two specialist discovery lanes.
- [x] Independent validation boundary.
- [x] Confirmed/rejected/blocked/risk-accepted lifecycle states.
- [x] Evidence-backed confirmed finding with control/proof fields (demonstrated by `npm run demo:secweave`).
- [x] Developer report with impact, remediation, and fix verification criteria.
- [x] Feedback loop and execution accounting.
- [x] Scope/approval enforcement, tests, schemas, benchmark, and runbook.
- [ ] Run the vertical slice against a selected real OSS repository.
- [ ] Execute Trivy binary in the target environment rather than fixture import only.
- [ ] Add a full MCP transport server and runtime proof/fix verification on an isolated target.

## Decision record

The original proposal PDFs are intentionally not stored in the repository. This Markdown document is the maintained, reviewable specification; changes should be made here and reflected in code/tests.
