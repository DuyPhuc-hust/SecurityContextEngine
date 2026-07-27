#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { readFileSync } from "node:fs";
import { SqliteStore } from "../core/state/sqlite-store.mjs";
import { inventoryGitRepository } from "../adapters/git/inventory.mjs";
import { baselineStatus } from "../adapters/cloudflare-security-audit/index.mjs";
import { initializeScan } from "../core/scan/initialize.mjs";
import { importSemgrepOutput, semgrepStatus } from "../adapters/semgrep/index.mjs";
import { executeSemgrepTask } from "../core/scheduler/semgrep-task.mjs";
import { buildProjectSummary, renderProjectMarkdown } from "../core/reporting/project-report.mjs";
import { scheduleIncrementalRescan } from "../core/incremental/rescan.mjs";
import { ingestTypeScriptInventory } from "../core/scan/whitebox.mjs";
import { retrieveContext } from "../core/graph/retrieval.mjs";
import { huntAccessControl } from "../agents/access-control-hunter/index.mjs";
import { planAccessControlValidation } from "../agents/validator/plan.mjs";
import { validateAccessControlStatically } from "../agents/validator/access-control-static.mjs";
import { importSarifFile } from "../adapters/sarif/index.mjs";
import { importCycloneDxFile } from "../adapters/cyclonedx/index.mjs";
import { importTrivyFile } from "../adapters/trivy/index.mjs";
import { claimAndExecuteDeterministic } from "../core/scheduler/deterministic-worker.mjs";
import { updateThreatModelFromFile } from "../core/threat-model/edit.mjs";
import { updateScopePolicyFromFile } from "../core/scope/edit.mjs";
import { scheduleCoverageGapfill } from "../core/coverage/gapfill.mjs";
import { huntAuthentication } from "../agents/auth-hunter/index.mjs";
import { huntInjection } from "../agents/injection-hunter/index.mjs";

const usage = `Security Context Engine CLI

Usage:
  security-context project:create <name> [--db <path>]
  security-context projects:list [--db <path>]
  security-context snapshot:create <project-id> <revision> [--db <path>]
  security-context task:create <project-id> <kind> [--snapshot <id>] [--scope <json>] [--priority <number>] [--db <path>]
  security-context tasks:list [--project <id>] [--db <path>]
  security-context task:state <task-id> <queued|running|blocked|completed|failed> [--db <path>]
  security-context task:claim --worker <id> [--lease-seconds <seconds>] [--project <id>] [--db <path>]
  security-context claim:add <project-id> <kind> <summary> --provenance <json> [--snapshot <id>] [--db <path>]
  security-context finding:create <project-id> <title> --invariant <text> [--snapshot <id>] [--db <path>]
  security-context finding:transition <finding-id> <state> [--reason <text>] [--db <path>]
  security-context git:inventory <project-id> <repository-path> [--snapshot <id>] [--db <path>]
  security-context scan:init <repository-path> [--name <project-name>] [--db <path>]
  security-context coverage:list <project-id> [--db <path>]
  security-context signals:list <project-id> [--db <path>]
  security-context semgrep:status
  security-context semgrep:import <project-id> <semgrep-json> --snapshot <id> [--db <path>]
  security-context semgrep:run <task-id> [--db <path>]
  security-context report:status <project-id> [--db <path>]
  security-context report:markdown <project-id> [--db <path>]
  security-context scan:diff <project-id> <repository-path> [--db <path>]
  security-context whitebox:typescript <project-id> <repository-path> --snapshot <id> [--db <path>]
  security-context graph:search <project-id> <query> --snapshot <id> [--db <path>]
  security-context graph:neighbors <project-id> <node-id> --snapshot <id> [--db <path>]
  security-context hunt:access-control <project-id> --snapshot <id> [--db <path>]
  security-context hypotheses:list <project-id> [--db <path>]
  security-context validate:access-control:plan <hypothesis-id> [--db <path>]
  security-context validate:access-control:static <task-id> [--db <path>]
  security-context sarif:import <project-id> <sarif-json> --snapshot <id> [--db <path>]
  security-context cyclonedx:import <project-id> <bom-json> --snapshot <id> [--db <path>]
  security-context trivy:import <project-id> <trivy-json> --snapshot <id> [--db <path>]
  security-context hunt:authentication <project-id> --snapshot <id> [--db <path>]
  security-context hunt:injection <project-id> --snapshot <id> [--db <path>]
  security-context scheduler:run-one --worker <id> [--project <id>] [--db <path>]
  security-context finding:accept <finding-id> [--db <path>]
  security-context evidence:add <project-id> <kind> <summary> --snapshot <id> --revision <rev> [--artifact-uri <uri>] [--observed <json>] [--db <path>]
  security-context finding:promote <hypothesis-id> <details-json-file> --evidence <id,id,...> [--db <path>]
  security-context finding:details <finding-id> [--db <path>]
  security-context finding:feedback <finding-id> <accepted|dismissed|fixed|risk-accepted> --reason <text> [--reviewer <name>] [--db <path>]
  security-context remediation:plan <finding-id> [--db <path>]
  security-context coverage:gapfill <project-id> --snapshot <id> [--db <path>]
  security-context threat-model:show <project-id> --snapshot <id> [--db <path>]
  security-context threat-model:update <project-id> <json-file> --snapshot <id> [--status <draft|reviewed>] [--db <path>]
  security-context scope:show <project-id> --snapshot <id> [--db <path>]
  security-context scope:update <project-id> <json-file> --snapshot <id> [--db <path>]
  security-context baseline:cloudflare:status
`;

const args = process.argv.slice(2);
const command = args.shift();
const option = (name, fallback = undefined) => {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  args.splice(index, 2);
  return value;
};
const json = (value, label) => { try { return JSON.parse(value); } catch { throw new Error(`${label} must be valid JSON`); } };
const output = (value) => console.log(JSON.stringify(value, null, 2));

try {
  if (!command || command === "help" || command === "--help") { console.log(usage); process.exit(0); }
  if (command === "baseline:cloudflare:status") { output(baselineStatus()); process.exit(0); }
  if (command === "semgrep:status") { output(semgrepStatus()); process.exit(0); }
  const dbPath = resolve(option("--db", ".security-context/context.db"));
  const store = new SqliteStore(dbPath);
  let result;
  switch (command) {
    case "project:create": result = store.createProject(args.join(" ")); break;
    case "projects:list": result = store.listProjects(); break;
    case "snapshot:create": result = store.createSnapshot(args[0], args[1]); break;
    case "task:create": result = store.createTask({ projectId: args[0], kind: args[1], snapshotId: option("--snapshot", null), scope: json(option("--scope", "{}"), "scope"), priority: Number(option("--priority", "0")) }); break;
    case "tasks:list": result = store.listTasks(option("--project", null)); break;
    case "task:state": store.updateTaskState(args[0], args[1]); result = { id: args[0], state: args[1] }; break;
    case "task:claim": result = store.claimNextTask({ workerId: option("--worker"), leaseSeconds: option("--lease-seconds", "300"), projectId: option("--project", null) }); break;
    case "claim:add": result = store.addClaim({ projectId: args[0], kind: args[1], summary: args[2], snapshotId: option("--snapshot", null), provenance: json(option("--provenance"), "provenance") }); break;
    case "finding:create": result = store.createFinding({ projectId: args[0], title: args[1], snapshotId: option("--snapshot", null), securityInvariant: option("--invariant") }); break;
    case "finding:transition": result = store.transitionFinding(args[0], args[1], option("--reason", null)); break;
    case "evidence:add": result = store.addEvidence({ projectId: args[0], kind: args[1], summary: args[2], snapshotId: option("--snapshot"), sourceRevision: option("--revision"), artifactUri: option("--artifact-uri", null), observed: json(option("--observed", "{}"), "observed") }); break;
    case "finding:promote": result = store.createConfirmedFindingFromHypothesis({ hypothesisId: args[0], details: JSON.parse(readFileSync(resolve(args[1]), "utf8")), evidenceIds: option("--evidence", "").split(",").map((value) => value.trim()).filter(Boolean) }); break;
    case "finding:details": {
      const finding = store.getFinding(args[0]);
      if (!finding) throw new Error(`Finding not found: ${args[0]}`);
      result = { finding, details: store.getFindingDetails(args[0]), feedback: store.listFeedback(args[0]) };
      break;
    }
    case "finding:feedback": result = store.recordDeveloperFeedback({ findingId: args[0], decision: args[1], reviewer: option("--reviewer", null), reason: option("--reason") }); break;
    case "git:inventory": {
      const inventory = await inventoryGitRepository(args[1]);
      const artifact = store.addArtifact({ projectId: args[0], snapshotId: option("--snapshot", null), kind: "git-inventory", uri: `git://${inventory.repositoryRoot}@${inventory.revision}` });
      result = { artifact, inventory };
      break;
    }
    case "scan:init": result = await initializeScan({ store, stateDirectory: dirname(dbPath), repositoryPath: args[0], projectName: option("--name", null) }); break;
    case "coverage:list": result = store.listCoverage(args[0]); break;
    case "signals:list": result = store.listSignals(args[0]); break;
    case "semgrep:import": result = importSemgrepOutput({ store, stateDirectory: dirname(dbPath), projectId: args[0], outputPath: args[1], snapshotId: option("--snapshot") }); break;
    case "semgrep:run": {
      const task = store.getTask(args[0]);
      if (!task) throw new Error(`Task not found: ${args[0]}`);
      result = await executeSemgrepTask({ store, stateDirectory: dirname(dbPath), task });
      break;
    }
    case "report:status": result = buildProjectSummary(store, args[0]); break;
    case "report:markdown": console.log(renderProjectMarkdown(buildProjectSummary(store, args[0]))); store.close(); process.exit(0);
    case "scan:diff": result = await scheduleIncrementalRescan({ store, stateDirectory: dirname(dbPath), projectId: args[0], repositoryPath: args[1] }); break;
    case "whitebox:typescript": result = await ingestTypeScriptInventory({ store, stateDirectory: dirname(dbPath), projectId: args[0], repositoryPath: args[1], snapshotId: option("--snapshot") }); break;
    case "graph:search": result = retrieveContext(store, { projectId: args[0], query: args[1], snapshotId: option("--snapshot") }); break;
    case "graph:neighbors": result = store.contextNeighborhood({ projectId: args[0], nodeId: args[1], snapshotId: option("--snapshot") }); break;
    case "hunt:access-control": result = huntAccessControl({ store, projectId: args[0], snapshotId: option("--snapshot") }); break;
    case "hypotheses:list": result = store.listHypotheses(args[0]); break;
    case "validate:access-control:plan": result = planAccessControlValidation({ store, hypothesisId: args[0] }); break;
    case "validate:access-control:static": result = validateAccessControlStatically({ store, taskId: args[0] }); break;
    case "sarif:import": result = importSarifFile({ store, stateDirectory: dirname(dbPath), projectId: args[0], path: args[1], snapshotId: option("--snapshot") }); break;
    case "cyclonedx:import": result = importCycloneDxFile({ store, stateDirectory: dirname(dbPath), projectId: args[0], path: args[1], snapshotId: option("--snapshot") }); break;
    case "trivy:import": result = importTrivyFile({ store, stateDirectory: dirname(dbPath), projectId: args[0], path: args[1], snapshotId: option("--snapshot") }); break;
    case "hunt:authentication": result = huntAuthentication({ store, projectId: args[0], snapshotId: option("--snapshot") }); break;
    case "hunt:injection": result = huntInjection({ store, projectId: args[0], snapshotId: option("--snapshot") }); break;
    case "scheduler:run-one": result = await claimAndExecuteDeterministic({ store, stateDirectory: dirname(dbPath), workerId: option("--worker"), projectId: option("--project", null) }); break;
    case "finding:accept": result = store.transitionFinding(args[0], "ACCEPTED", "human acceptance"); break;
    case "remediation:plan": result = store.createRemediationTask(args[0]); break;
    case "coverage:gapfill": result = scheduleCoverageGapfill({ store, projectId: args[0], snapshotId: option("--snapshot") }); break;
    case "threat-model:show": result = store.getLatestThreatModel(args[0], option("--snapshot")); break;
    case "threat-model:update": result = updateThreatModelFromFile({ store, stateDirectory: dirname(dbPath), projectId: args[0], path: args[1], snapshotId: option("--snapshot"), status: option("--status", "draft") }); break;
    case "scope:show": result = store.getLatestScopePolicy(args[0], option("--snapshot")); break;
    case "scope:update": result = updateScopePolicyFromFile({ store, stateDirectory: dirname(dbPath), projectId: args[0], path: args[1], snapshotId: option("--snapshot") }); break;
    default: throw new Error(`Unknown command: ${command}`);
  }
  store.close();
  output(result);
} catch (error) {
  console.error(`Error: ${error.message}`);
  console.error(usage);
  process.exit(1);
}
