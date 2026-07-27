---
name: security-hunt
description: Run scoped, evidence-first security assessments through the Security Context Engine. Use for repository security review, incremental rescan, threat-model creation, validation planning, or finding remediation when the target scope and authorization need to be recorded.
---

# Security Hunt

Use the core CLI or MCP server; do not store durable context only in this skill or chat history.

## Workflow

1. Parse target, requested mode, permitted actions, and output location.
2. Load `references/safety-policy.md`; request approval for out-of-scope active testing.
3. Create or load a project snapshot and threat model. Record assumptions separately from facts.
4. Schedule Recon, Hunt, and independent Validate tasks. Normalize tool output as signals.
5. Retrieve only the route/symbol/graph slice required by each task. Persist provenance, coverage, cost, and evidence.
6. Report confirmed findings only with a reproducible proof or equivalent evidence. Mark inaccessible proof as `VALIDATION_BLOCKED`.
7. For remediation, create one minimal patch task per accepted finding and re-run the original proof plus nearby-bypass checks.

## Required reporting language

State coverage and proof gaps. Say “no confirmed findings in this scope and coverage,” never “the system has no vulnerabilities.”

## References

- Read `references/safety-policy.md` before browser/API execution.
- Read `references/reporting.md` when producing finding output.
