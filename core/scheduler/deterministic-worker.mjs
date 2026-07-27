import { ingestTypeScriptInventory } from "../scan/whitebox.mjs";
import { huntAccessControl } from "../../agents/access-control-hunter/index.mjs";
import { huntAuthentication } from "../../agents/auth-hunter/index.mjs";
import { huntInjection } from "../../agents/injection-hunter/index.mjs";
import { executeSemgrepTask } from "./semgrep-task.mjs";

function complete(store, task, summary, coverage = null) {
  store.updateTaskState(task.id, "completed");
  if (coverage) store.upsertCoverage({ projectId: task.project_id, snapshotId: task.snapshot_id, sourceRevision: task.scope.source_revision, depth: "partial", evidenceIds: coverage.evidenceIds, proofGaps: coverage.proofGaps, reviewedEntities: coverage.reviewedEntities, area: "repository", attackClass: coverage.attackClass });
  store.recordAgentRun({ projectId: task.project_id, taskId: task.id, provider: "deterministic", taskType: task.kind, outcome: summary });
}

export async function executeDeterministicTask({ store, stateDirectory, task }) {
  if (!task || task.state !== "running") throw new Error("Claim a task before execution.");
  if (task.kind === "semgrep-sast") return executeSemgrepTask({ store, stateDirectory, task });
  if (task.kind === "typescript-inventory") {
    const result = await ingestTypeScriptInventory({ store, stateDirectory, projectId: task.project_id, snapshotId: task.snapshot_id, repositoryPath: task.scope.repository_root });
    complete(store, task, `extracted ${result.inventory.symbols.length} symbols${result.cacheHit ? " (cache hit)" : ""}`);
    return { state: "completed", result };
  }
  const handlers = {
    "access-control-hunt": [huntAccessControl, "broken-access-control"],
    "auth-hunt": [huntAuthentication, "authentication"],
    "injection-hunt": [huntInjection, "injection"]
  };
  const handler = handlers[task.kind];
  if (handler) {
    const result = handler[0]({ store, projectId: task.project_id, snapshotId: task.snapshot_id });
    complete(store, task, `created ${result.hypotheses.length} hypotheses`, { attackClass: handler[1], evidenceIds: [result.artifact.id], proofGaps: ["Independent validation is pending."], reviewedEntities: [`${result.scannedRoutes ?? result.sinks ?? 0} static candidates`] });
    return { state: "completed", result };
  }
  store.updateTaskState(task.id, "blocked", { error: "Requires an agent provider or a dedicated executor." });
  store.recordAgentRun({ projectId: task.project_id, taskId: task.id, provider: "deterministic", taskType: task.kind, outcome: "blocked: no deterministic executor" });
  return { state: "blocked", reason: "No deterministic executor for task kind" };
}

export async function claimAndExecuteDeterministic({ store, stateDirectory, workerId, projectId = null }) {
  const task = store.claimNextTask({ workerId, projectId, kinds: ["semgrep-sast", "typescript-inventory", "access-control-hunt", "auth-hunt", "injection-hunt"] });
  if (!task) return { state: "idle" };
  return { task, execution: await executeDeterministicTask({ store, stateDirectory, task }) };
}
