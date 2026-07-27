# Cloudflare Security Audit baseline

The repository is cloned unchanged at `external/cloudflare-security-audit-skill` and pinned in [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

## Adopted design

- Six stages: recon, hunt, validation, reporting, structured output, independent verification.
- Discovery and validation are different agent roles.
- Findings need concrete impact and a reproducible scenario.
- The upstream `findings.json` validator is usable through this repository's adapter.

## Deliberately not adopted as core state

The baseline stores its audit knowledge in output files per run. This engine instead persists snapshots, provenance, hypotheses, findings, evidence, tasks, and coverage in its state store. The adapter therefore treats upstream output as an imported artifact/signal, not as the canonical source of truth.

## Updating upstream

Review the upstream diff and license before changing the pinned revision. Never edit files inside `external/cloudflare-security-audit-skill`; place integrations under `adapters/cloudflare-security-audit/`.
