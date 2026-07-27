import { resolve } from "node:path";
import { importSemgrepDocument, runSemgrep } from "../../adapters/semgrep/index.mjs";

/** Execute only the deterministic Semgrep lane; never promote output beyond SIGNAL. */
export async function executeSemgrepTask({ store, stateDirectory, task, run = runSemgrep }) {
  if (task.kind !== "semgrep-sast") throw new Error(`Task ${task.id} is not a semgrep-sast task`);
  if (task.state !== "running") throw new Error("Claim the task before running it");
  const startedAt = Date.now();
  try {
    const raw = await run({ targetPath: task.scope.repository_root, configPath: resolve(task.scope.semgrep_config) });
    const imported = importSemgrepDocument({ store, stateDirectory, projectId: task.project_id, snapshotId: task.snapshot_id, raw });
    store.updateTaskState(task.id, "completed");
    store.recordAgentRun({ projectId: task.project_id, taskId: task.id, provider: "semgrep", taskType: "semgrep-sast", schemaVersion: "semgrep-json/v1", latencyMs: Date.now() - startedAt, outcome: `imported ${imported.signals.length} signals` });
    return { state: "completed", ...imported };
  } catch (error) {
    store.updateTaskState(task.id, "blocked", { error: error.message });
    store.recordAgentRun({ projectId: task.project_id, taskId: task.id, provider: "semgrep", taskType: "semgrep-sast", latencyMs: Date.now() - startedAt, outcome: `blocked: ${error.message}` });
    return { state: "blocked", error: error.message };
  }
}
