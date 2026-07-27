# Security Context Engine — Project Specification

## Status

This document is the repository-native specification for the Security Context Engine. It replaces the original project-start PDF as the version-controlled source of truth.

## Vision

Build a persistent, model-agnostic security harness that can be embedded into Claude Code, Codex, and other coding agents. The engine maintains system security context and gives each hunter or validator only the context slice it needs.

The engine is not just an AI scanner or an OWASP checklist. Its durable advantage is persistent context, cross-system relationships, incremental semantic updates, cost-aware orchestration, and evidence-first findings.

## Core principles

1. Models are stateless compute; durable context lives outside the model.
2. Deterministic orchestration owns queueing, retries, leases, budgets, scope, cache, deduplication, approvals, and state transitions.
3. Discovery and validation are independent roles.
4. Retrieval is narrow and need-driven: exact symbol/route, graph neighborhood, source-to-sink slice, identity/control context, configuration, runtime observations, then lexical fallback.
5. A tool alert is a signal, not a vulnerability finding.
6. A confirmed finding requires source revision, invariant, control/proof evidence, impact, limitations, remediation, and fix verification criteria.
7. Active testing is opt-in, scoped, approved, isolated, and redacted.

## Functional scope

- Multi-project SQLite state with Git snapshots and resumable task leases.
- Git inventory, TypeScript/JavaScript whitebox context, Semgrep, Trivy, SARIF, and CycloneDX adapters.
- Discovery lanes for authentication, authorization, injection, recon, facts, and deterministic tool signals.
- Hypothesis store, independent validation attempts, finding state machine, remediation planning, developer feedback, and reports.
- Incremental rescans based on changed paths and affected coverage.
- CLI, Agent Kit, and transport-neutral MCP boundary for embedding into agent hosts.

## Non-goals for the MVP

- Production CI/CD deployment.
- Mobile, binary, or multi-stack coverage beyond the selected pilot stack.
- Unapproved active testing against production.
- Organization-wide learning or autonomous patch merging.

## Quality gates

- `npm run check`
- `npm test`
- `npm run validate:schemas`
- `npm run benchmark`
- `npm run demo:secweave`

See [SecWeave alignment](secweave-alignment.md) for MVP acceptance mapping and remaining gaps.
