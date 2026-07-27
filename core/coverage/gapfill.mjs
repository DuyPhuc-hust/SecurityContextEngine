const taskForAttackClass = {
  "broken-access-control": "access-control-hunt",
  "access-control": "access-control-hunt",
  authentication: "auth-hunt",
  injection: "injection-hunt",
  "security-misconfiguration": "fact-extraction",
  "supply-chain": "semgrep-sast"
};

/** Schedule only coverage gaps not already represented by an active task. */
export function scheduleCoverageGapfill({ store, projectId, snapshotId }) {
  const snapshot = store.getSnapshot(snapshotId);
  if (!snapshot) throw new Error(`Snapshot not found: ${snapshotId}`);
  const coverage = store.listCoverage(projectId).filter((record) => record.snapshot_id === snapshotId);
  const existing = store.listTasks(projectId).filter((task) => task.snapshot_id === snapshotId && ["queued", "running"].includes(task.state));
  const scheduled = [];
  const gaps = coverage.filter((record) => record.depth !== "deep" || record.stale === 1);
  for (const gap of gaps) {
    const kind = taskForAttackClass[gap.attack_class];
    if (!kind || existing.some((task) => task.kind === kind)) continue;
    scheduled.push(store.createTask({
      projectId,
      snapshotId,
      kind,
      priority: gap.depth === "none" || gap.stale === 1 ? 1 : 0.5,
      scope: { source_revision: snapshot.revision, coverage_gap: { area: gap.area, attack_class: gap.attack_class, current_depth: gap.depth, stale: gap.stale === 1 } }
    }));
  }
  return { gaps: gaps.map((gap) => ({ area: gap.area, attackClass: gap.attack_class, depth: gap.depth, stale: gap.stale === 1 })), scheduled };
}
