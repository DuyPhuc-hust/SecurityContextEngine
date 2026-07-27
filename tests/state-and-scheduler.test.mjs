import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteStore } from "../core/state/sqlite-store.mjs";

function newStore() {
  const directory = mkdtempSync(join(tmpdir(), "sce-test-"));
  return new SqliteStore(join(directory, "context.db"));
}

test("claims only a supported task kind and tracks a lease", () => {
  const store = newStore();
  const project = store.createProject("state-test");
  const snapshot = store.createSnapshot(project.id, "revision-1");
  store.createTask({ projectId: project.id, snapshotId: snapshot.id, kind: "recon", priority: 10 });
  const expected = store.createTask({ projectId: project.id, snapshotId: snapshot.id, kind: "typescript-inventory", priority: 1 });
  const claimed = store.claimNextTask({ workerId: "test-worker", kinds: ["typescript-inventory"] });
  assert.equal(claimed.id, expected.id);
  assert.equal(claimed.state, "running");
  assert.equal(claimed.attempts, 1);
  assert.ok(claimed.lease_expires_at);
  store.close();
});

test("content cache is keyed and returned with parsed JSON", () => {
  const store = newStore();
  store.setCache({ cacheKey: "inventory:p:r:v", sourceRevision: "r", value: { routes: 2 } });
  assert.deepEqual(store.getCache("inventory:p:r:v").value, { routes: 2 });
  assert.equal(store.getCache("missing"), null);
  store.close();
});

test("confirmed promotion requires explicit evidence and records developer feedback", () => {
  const store = newStore();
  const project = store.createProject("promotion-test");
  const snapshot = store.createSnapshot(project.id, "revision-1");
  const hypothesis = store.createHypothesis({ projectId: project.id, snapshotId: snapshot.id, fingerprint: "fp", title: "Broken authorization", attackClass: "broken-access-control", securityInvariant: "Users cannot read another tenant", rank: 1, rationale: "route lacks ownership check" });
  assert.throws(() => store.createConfirmedFindingFromHypothesis({ hypothesisId: hypothesis.id, details: {}, evidenceIds: [] }), /explicit evidence/);
  const evidence = store.addEvidence({ projectId: project.id, snapshotId: snapshot.id, kind: "runtime-proof", summary: "Tenant B received Tenant A record", sourceRevision: "revision-1", observed: { status: 200 } });
  const finding = store.createConfirmedFindingFromHypothesis({ hypothesisId: hypothesis.id, evidenceIds: [evidence.id], details: { attacker_identity: "tenant B user", preconditions: "authenticated", entry_point: "GET /records/:id", attack_path: "request id -> query", control_case: "same tenant returns 200", proof_case: "cross tenant returns 200", observed_result: "foreign record returned", impact: "cross-tenant disclosure", confidence: 0.98, root_cause: "missing ownership predicate", remediation: "add tenant predicate", fix_verification: "replay proof and control cases" } });
  assert.equal(finding.state, "CONFIRMED");
  store.recordDeveloperFeedback({ findingId: finding.id, decision: "risk-accepted", reviewer: "dev", reason: "legacy endpoint, tracked exception" });
  assert.equal(store.getFinding(finding.id).state, "RISK_ACCEPTED");
  store.close();
});
