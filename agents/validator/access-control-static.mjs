import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ownershipPattern = /authorize|ownership|tenant|permission|role/i;

function routeFromHypothesis(title) {
  const match = title.match(/at ([A-Z]+) (.+)$/);
  return match ? { method: match[1], path: match[2] } : null;
}

/** Independent static review. It may reject, but cannot confirm exploitability without proof. */
export function validateAccessControlStatically({ store, taskId }) {
  const task = store.getTask(taskId);
  if (!task || task.kind !== "validate-access-control") throw new Error("Expected a validate-access-control task");
  if (task.state !== "running") throw new Error("Claim the validation task before running it");
  const hypothesis = store.getHypothesis(task.scope.hypothesis_id);
  if (!hypothesis) throw new Error("Validation task references a missing hypothesis");
  const artifact = store.latestArtifact({ projectId: hypothesis.project_id, snapshotId: hypothesis.snapshot_id, kind: "typescript-inventory" });
  if (!artifact) throw new Error("Static inventory artifact is unavailable");
  const inventory = JSON.parse(readFileSync(resolve(process.cwd(), artifact.uri), "utf8"));
  const target = routeFromHypothesis(hypothesis.title);
  const route = target && inventory.routes.find((item) => item.method === target.method && item.path === target.path);
  const directOwnershipControl = route && [...route.middleware, route.handler].some((item) => ownershipPattern.test(item));
  if (directOwnershipControl) {
    store.updateHypothesisState(hypothesis.id, "REJECTED");
    const attempt = store.recordValidationAttempt({ hypothesisId: hypothesis.id, taskId, mode: "static", outcome: "rejected", evidenceIds: [artifact.id], details: { reason: "Recognized route-level ownership/authorization control.", route } });
    store.updateTaskState(taskId, "completed");
    return { state: "REJECTED", attempt };
  }
  store.updateHypothesisState(hypothesis.id, "VALIDATION_BLOCKED");
  const attempt = store.recordValidationAttempt({ hypothesisId: hypothesis.id, taskId, mode: "static", outcome: "blocked", evidenceIds: [artifact.id], details: { reason: "Static review could not prove or disprove object-level authorization. Runtime control/proof cases are required.", wishlist: task.scope.runtime_requirements, route } });
  store.updateTaskState(taskId, "blocked", { error: "Runtime control/proof cases required" });
  return { state: "VALIDATION_BLOCKED", attempt, wishlist: task.scope.runtime_requirements };
}
