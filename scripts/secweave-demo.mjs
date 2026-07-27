import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { SqliteStore } from "../core/state/sqlite-store.mjs";
import { initializeScan } from "../core/scan/initialize.mjs";
import { claimAndExecuteDeterministic } from "../core/scheduler/deterministic-worker.mjs";
import { importTrivyFile } from "../adapters/trivy/index.mjs";
import { buildProjectSummary } from "../core/reporting/project-report.mjs";

// Reproducible SecWeave MVP vertical slice: scope -> discovery -> signal -> evidence -> confirmed finding.
const workspace = mkdtempSync(join(tmpdir(), "secweave-demo-"));
const repositoryPath = join(workspace, "repo");
const stateDirectory = join(workspace, "state");
try {
  cpSync("fixtures/whitebox/app.ts", join(workspace, "app.ts"));
  execFileSync("git", ["init", "-q", repositoryPath]);
  writeFileSync(join(repositoryPath, "app.ts"), readFileSync("fixtures/whitebox/app.ts"));
  execFileSync("git", ["-C", repositoryPath, "add", "app.ts"]);
  execFileSync("git", ["-C", repositoryPath, "-c", "user.name=SecWeave Demo", "-c", "user.email=demo@example.invalid", "commit", "-qm", "seed"]);
  const store = new SqliteStore(join(stateDirectory, "context.db"));
  const initialized = await initializeScan({ store, stateDirectory, repositoryPath, projectName: "secweave-demo" });
  for (let index = 0; index < 8; index += 1) await claimAndExecuteDeterministic({ store, stateDirectory, workerId: "demo-worker", projectId: initialized.project.id });
  const trivy = importTrivyFile({ store, stateDirectory, projectId: initialized.project.id, snapshotId: initialized.snapshot.id, path: "fixtures/trivy/sample.json" });
  const hypothesis = store.listHypotheses(initialized.project.id).find((item) => item.attack_class === "broken-access-control") || store.listHypotheses(initialized.project.id)[0];
  if (!hypothesis) throw new Error("Demo did not produce a hypothesis");
  const control = store.addEvidence({ projectId: initialized.project.id, snapshotId: initialized.snapshot.id, kind: "control-case", summary: "Same-tenant request is authorized", sourceRevision: initialized.snapshot.revision, observed: { status: 200, tenant_match: true } });
  const proof = store.addEvidence({ projectId: initialized.project.id, snapshotId: initialized.snapshot.id, kind: "proof-case", summary: "Cross-tenant request returned another tenant's record", sourceRevision: initialized.snapshot.revision, observed: { status: 200, tenant_match: false, record_exposed: true } });
  const finding = store.createConfirmedFindingFromHypothesis({ hypothesisId: hypothesis.id, evidenceIds: [control.id, proof.id], details: { attacker_identity: "authenticated tenant user", preconditions: "valid session and predictable record identifier", entry_point: "record lookup endpoint", attack_path: "request identifier -> lookup without tenant predicate", control_case: control.summary, proof_case: proof.summary, observed_result: "foreign record returned with HTTP 200", impact: "cross-tenant data disclosure", confidence: 0.95, root_cause: "missing object-level authorization predicate", remediation: "enforce tenant ownership in the query and service boundary", fix_verification: "replay proof and control cases after patch", limitations: "fixture demo, no production traffic" } });
  console.log(JSON.stringify({ project: initialized.project, snapshot: initialized.snapshot, trivySignals: trivy.normalizedCount, promotedFinding: { id: finding.id, state: finding.state, evidenceIds: JSON.parse(finding.evidence_ids_json) }, report: buildProjectSummary(store, initialized.project.id) }, null, 2));
  store.close();
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
