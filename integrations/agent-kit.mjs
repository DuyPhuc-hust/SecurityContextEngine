import { dirname, resolve } from "node:path";
import { SqliteStore } from "../core/state/sqlite-store.mjs";
import { initializeScan } from "../core/scan/initialize.mjs";
import { claimAndExecuteDeterministic } from "../core/scheduler/deterministic-worker.mjs";
import { importTrivyFile } from "../adapters/trivy/index.mjs";
import { buildProjectSummary } from "../core/reporting/project-report.mjs";
import { retrieveContext } from "../core/graph/retrieval.mjs";

/**
 * Embeddable API for Claude Code, Codex, MCP hosts, or another agent runtime.
 * The host owns the agent loop; this kit owns durable scope, evidence, and state.
 */
export function createSecurityContextAgent({ dbPath = ".security-context/context.db", stateDirectory = null } = {}) {
  const databasePath = resolve(dbPath);
  const store = new SqliteStore(databasePath);
  const artifactDirectory = resolve(stateDirectory ?? dirname(databasePath));
  return {
    store,
    async initialize({ repositoryPath, projectName = null }) {
      return initializeScan({ store, stateDirectory: artifactDirectory, repositoryPath, projectName });
    },
    async runDiscovery({ projectId, workerId = "embedded-agent", maxTasks = 10 } = {}) {
      const runs = [];
      for (let index = 0; index < maxTasks; index += 1) {
        const run = await claimAndExecuteDeterministic({ store, stateDirectory: artifactDirectory, workerId, projectId });
        runs.push(run);
        if (run.state === "idle") break;
      }
      return runs;
    },
    importTrivy({ projectId, snapshotId, path }) {
      return importTrivyFile({ store, stateDirectory: artifactDirectory, projectId, snapshotId, path });
    },
    context({ projectId, snapshotId, query, limit = 20 }) {
      return retrieveContext(store, { projectId, snapshotId, query, limit });
    },
    evidence(input) { return store.addEvidence(input); },
    promote(input) { return store.createConfirmedFindingFromHypothesis(input); },
    feedback(input) { return store.recordDeveloperFeedback(input); },
    report(projectId) { return buildProjectSummary(store, projectId); },
    close() { store.close(); }
  };
}
