# Security Context Engine

Persistent, model-agnostic security harness. It retains context across code, runtime observations, identity, evidence, coverage, and findings so later runs analyze only the affected surface.

## Structure

- `skills/security-hunt/`: thin Agent Skill adapter for scoped security hunts.
- `core/`: durable contracts, state, policy, graph, findings, evidence, coverage, and incremental boundaries.
- `schemas/`: canonical JSON contracts created before tool/provider integration.
- `adapters/`: integrations for Git, SAST/DAST/SCA, browser, and interchange formats.
- `analyzers/`: whitebox, blackbox, partitioning, and impact analysis.
- `agents/`: independent recon, hunting, validation, reporting, and remediation roles.
- `providers/`: model-agnostic provider abstraction.
- `policies/`: explicit scope and approval policy.

## MVP order

1. SQLite state/artifact store and schema validation.
2. Git inventory plus Semgrep and Trivy adapters.
3. Persistent Recon → Hunt → Validate tasks and coverage records.
4. Independent validator and evidence artifacts.
5. Incremental impact closure; active runtime validation only against an approved isolated target.

A tool alert is a signal, not a confirmed finding. Confirmed findings preserve a target revision, invariant, control/proof case, observed result, and evidence.

## External baseline

The untouched MIT-licensed Cloudflare Security Audit Skill baseline is kept in `external/cloudflare-security-audit-skill`. Its status and validator are exposed through `adapters/cloudflare-security-audit/`; see [baseline notes](docs/baselines/cloudflare-security-audit.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

## First working commands

The CLI is dependency-free on Node.js 24+ and stores state in `.security-context/context.db` by default.

```sh
npm run cli -- project:create demo-api
npm run cli -- snapshot:create <project-id> <git-revision>
npm run cli -- task:create <project-id> recon --snapshot <snapshot-id> --scope '{"path":"."}'
npm run cli -- tasks:list --project <project-id>
npm run cli -- git:inventory <project-id> /path/to/target --snapshot <snapshot-id>
npm run cli -- baseline:cloudflare:status
```

Create the first persistent context for a Git repository:

```sh
npm run cli -- scan:init /path/to/target --name target-name
npm run cli -- task:claim --worker local-recon
```

`scan:init` writes immutable Git-inventory and draft-threat-model artifacts, creates provenance-backed claims, seeds the coverage matrix, and schedules Recon plus three specialist hunt lanes. It does not perform active runtime testing.

Repeated `scan:init` calls for the same project and Git revision resume existing state instead of duplicating tasks. TypeScript inventory is cached by project, source revision, and extractor version.

## Quality checks

```sh
npm run check
npm test
npm run validate:schemas
npm run benchmark
```

Semgrep output is imported as a `SIGNAL`, never a confirmed finding:

```sh
npm run cli -- semgrep:import <project-id> semgrep.json --snapshot <snapshot-id>
npm run cli -- signals:list <project-id>
```

The locally scoped baseline rules in `rules/semgrep/` are scheduled as `semgrep-sast`. Claim the task first, then run it; environment/tool failures are recorded as a blocked task with an audit record.

Runtime control/proof execution is guarded by the primary-target allowlist, explicit approval, and safe HTTP methods. See [runtime validation contract](docs/runtime-validation.md).

Import static-analysis output from any SARIF-compatible tool as signals:

```sh
npm run cli -- sarif:import <project-id> results.sarif.json --snapshot <snapshot-id>
```

Import a CycloneDX SBOM to add dependency nodes/edges and dependency vulnerability signals:

```sh
npm run cli -- cyclonedx:import <project-id> bom.json --snapshot <snapshot-id>
```

See [model routing](docs/model-routing.md) for the provider capability contract and independent-validation rule.

For an accepted confirmed finding, create exactly one remediation task:

```sh
npm run cli -- finding:accept <finding-id>
npm run cli -- remediation:plan <finding-id>
```

Create work for missing or stale coverage without duplicating an active lane:

```sh
npm run cli -- coverage:gapfill <project-id> --snapshot <snapshot-id>
```

Threat models are versioned and editable. Update with a JSON document that follows `schemas/threat-model.schema.json`:

```sh
npm run cli -- threat-model:show <project-id> --snapshot <snapshot-id>
npm run cli -- threat-model:update <project-id> threat-model.json --snapshot <snapshot-id> --status reviewed
```

Scope policy is also versioned per snapshot. It is the source of truth for target mode and active-testing approval:

```sh
npm run cli -- scope:show <project-id> --snapshot <snapshot-id>
npm run cli -- scope:update <project-id> scope-policy.json --snapshot <snapshot-id>
```

Three static specialist hunters are now available. They produce hypotheses only:

```sh
npm run cli -- hunt:access-control <project-id> --snapshot <snapshot-id>
npm run cli -- hunt:authentication <project-id> --snapshot <snapshot-id>
npm run cli -- hunt:injection <project-id> --snapshot <snapshot-id>
```

Run the next deterministic scheduled task (inventory, Semgrep, or specialist hunt):

```sh
npm run cli -- scheduler:run-one --worker local-worker --project <project-id>
```

Review persistent state without overstating security posture:

```sh
npm run cli -- report:status <project-id>
npm run cli -- report:markdown <project-id>
```

Project and snapshot references can use a project name, an 8-character short ID, or a snapshot revision prefix:

```sh
npm run cli -- projects:list
npm run cli -- snapshots:list secweave-demo
npm run cli -- project:show secweave-demo
```

Snapshot labels are also friendly: `snap-001`, `snap-002`, …; the underlying Git revision remains visible as `revision_short` when needed.

## Nhúng vào agent

Agent host có thể dùng API JavaScript thay vì gọi CLI trực tiếp:

```js
import { createSecurityContextAgent } from "./integrations/agent-kit.mjs";

const security = createSecurityContextAgent({ dbPath: ".security-context/context.db" });
const run = await security.initialize({ repositoryPath: "/path/to/target", projectName: "target-api" });
await security.runDiscovery({ projectId: run.project.id, workerId: "my-agent" });
const context = security.context({ projectId: run.project.id, snapshotId: run.snapshot.id, query: "GET /users/:id" });
const report = security.report(run.project.id);
security.close();
```

Agent vẫn phải dùng `evidence()` và `promote()` để tạo finding; discovery không tự động biến thành finding xác nhận. `integrations/mcp-boundary.mjs` cung cấp lớp tool transport-neutral cho MCP host.

Schedule only change impact after a later Git commit:

```sh
npm run cli -- scan:diff <project-id> /path/to/target
```

Build TypeScript/JavaScript whitebox context (symbols, imports, route candidates, sources, sinks, and control candidates):

```sh
npm run cli -- whitebox:typescript <project-id> /path/to/target --snapshot <snapshot-id>
```

Retrieve the narrow context needed for a hunter or validator:

```sh
npm run cli -- graph:search <project-id> 'GET /users/:id' --snapshot <snapshot-id>
npm run cli -- graph:neighbors <project-id> <node-id> --snapshot <snapshot-id>
```

Generate conservative broken-access-control hypotheses, then schedule independent validation:

```sh
npm run cli -- hunt:access-control <project-id> --snapshot <snapshot-id>
npm run cli -- validate:access-control:plan <hypothesis-id>
```

Claim the resulting validation task, then run static validation. If proof needs runtime identities/objects, the system records `VALIDATION_BLOCKED` rather than a false claim:

```sh
npm run cli -- task:claim --worker validator
npm run cli -- validate:access-control:static <validation-task-id>
```

## SecWeave MVP vertical slice

Run the reproducible demo that exercises SQLite persistence, deterministic discovery, Trivy signal normalization, explicit control/proof evidence, and promotion to a developer-ready `CONFIRMED` finding:

```sh
npm run demo:secweave
```

For a real project, add evidence explicitly and promote a hypothesis only after independent validation:

```sh
npm run cli -- evidence:add <project-id> proof-case 'cross-tenant record returned' --snapshot <snapshot-id> --revision <git-revision> --observed '{"status":200}'
npm run cli -- finding:promote <hypothesis-id> details.json --evidence <proof-evidence-id>,<control-evidence-id>
npm run cli -- finding:feedback <finding-id> accepted --reviewer developer --reason 'Reproduced and scheduled remediation'
```
