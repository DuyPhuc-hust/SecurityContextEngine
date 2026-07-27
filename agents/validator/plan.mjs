export function planAccessControlValidation({ store, hypothesisId }) {
  const hypothesis = store.getHypothesis(hypothesisId);
  if (!hypothesis) throw new Error(`Hypothesis not found: ${hypothesisId}`);
  const task = store.createTask({
    projectId: hypothesis.project_id,
    snapshotId: hypothesis.snapshot_id,
    kind: "validate-access-control",
    priority: hypothesis.rank,
    scope: {
      hypothesis_id: hypothesis.id,
      attacker_identity: "tenant-A test user",
      control_case: "Tenant A accesses an object owned by tenant A.",
      proof_case: "Tenant A attempts to access an equivalent object owned by tenant B.",
      runtime_requirements: ["approved isolated target", "two test identities", "cross-tenant test objects"],
      mode: "static-review-first"
    }
  });
  store.updateHypothesisState(hypothesis.id, "VALIDATION_PLANNED");
  return { hypothesis, task };
}
