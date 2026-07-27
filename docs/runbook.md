# SecWeave-aligned runbook

## Repeatable vertical slice

1. `security-context scan:init <repo>` creates a resumable SQLite project/snapshot and scope-controlled tasks.
2. Import deterministic signals with `semgrep:import`, `trivy:import`, SARIF, or CycloneDX.
3. Run specialist lanes and validation tasks; discovery does not promote findings by itself.
4. Add proof/control evidence with `evidence:add`.
5. Promote only an evidence-backed hypothesis with `finding:promote`; the command requires attacker, preconditions, entry point, attack path, control case, proof case, impact, root cause, remediation, and fix verification.
6. Let a developer record `finding:feedback` as accepted, dismissed, fixed, or risk-accepted. Reports expose the full developer-ready record.

## Safety gates

- Scope and approval policy are stored per snapshot. Active testing is disabled unless explicitly enabled.
- Runtime evidence must be redacted and linked to a source revision.
- A confirmed finding cannot be created without persisted evidence IDs; a hypothesis alone is never a finding.
- Trivy and Semgrep outputs are normalized into the same signal store so downstream lanes remain tool-independent.

## Resume and failure handling

SQLite task leases make interrupted runs resumable. Re-run the scheduler for queued or expired tasks; inspect `report:status` and `coverage:list` before widening scope.
