import { basename, resolve } from "node:path";
import { inventoryGitRepository } from "../../adapters/git/inventory.mjs";
import { writeJsonArtifact } from "../artifacts/json-artifact.mjs";
import { createInitialThreatModel } from "../threat-model/defaults.mjs";
import { calculatePriority } from "../scheduler/priority.mjs";
import { createDefaultScopePolicy } from "../scope/default-policy.mjs";

const initialTasks = [
  ["semgrep-sast", { expectedRisk: 0.8, expectedInformationGain: 0.6, coverageGap: 1, estimatedCost: 0.2 }],
  ["typescript-inventory", { expectedRisk: 1, expectedInformationGain: 1, coverageGap: 1, estimatedCost: 0.3 }],
  ["recon", { expectedRisk: 1, expectedInformationGain: 1, coverageGap: 1, estimatedCost: 1 }],
  ["fact-extraction", { expectedRisk: 0.8, expectedInformationGain: 1, coverageGap: 1, estimatedCost: 0.7 }],
  ["access-control-hunt", { expectedRisk: 1, expectedInformationGain: 0.9, coverageGap: 1, estimatedCost: 1 }],
  ["auth-hunt", { expectedRisk: 0.9, expectedInformationGain: 0.8, coverageGap: 1, estimatedCost: 1 }],
  ["injection-hunt", { expectedRisk: 0.9, expectedInformationGain: 0.8, coverageGap: 1, estimatedCost: 1 }]
];

export async function initializeScan({ store, stateDirectory, repositoryPath, projectName = null }) {
  const repositoryRoot = resolve(repositoryPath);
  const inventory = await inventoryGitRepository(repositoryRoot);
  const project = store.findOrCreateProject(projectName ?? basename(repositoryRoot));
  const existingSnapshot = store.getSnapshotByRevision(project.id, inventory.revision);
  if (existingSnapshot) {
    const existingTasks = store.listTasks(project.id).filter((task) => task.snapshot_id === existingSnapshot.id);
    if (existingTasks.length) return { resumed: true, project, snapshot: existingSnapshot, inventory, tasks: existingTasks };
  }
  const snapshot = store.createSnapshot(project.id, inventory.revision);
  const inventoryFile = writeJsonArtifact({ stateDirectory, projectId: project.id, snapshotId: snapshot.id, name: "git-inventory", value: inventory });
  const inventoryArtifact = store.addArtifact({ projectId: project.id, snapshotId: snapshot.id, kind: "git-inventory", uri: inventoryFile.uri, contentHash: inventoryFile.contentHash });
  const threatModel = createInitialThreatModel({ repositoryRoot, inventory });
  const threatModelFile = writeJsonArtifact({ stateDirectory, projectId: project.id, snapshotId: snapshot.id, name: "threat-model", value: threatModel });
  const threatModelArtifact = store.addArtifact({ projectId: project.id, snapshotId: snapshot.id, kind: "threat-model", uri: threatModelFile.uri, contentHash: threatModelFile.contentHash });
  const persistedThreatModel = store.saveThreatModel({ projectId: project.id, snapshotId: snapshot.id, document: threatModel, artifactId: threatModelArtifact.id });
  const persistedScopePolicy = store.saveScopePolicy({ projectId: project.id, snapshotId: snapshot.id, document: createDefaultScopePolicy() });
  const provenance = { origin: "deterministic-tool", artifact_ids: [inventoryArtifact.id], source_revision: inventory.revision, extractor_version: "git-inventory/v1", confidence: 1, created_at: new Date().toISOString(), stale: false };
  const facts = [
    store.addClaim({ projectId: project.id, snapshotId: snapshot.id, kind: "fact", summary: `Repository has ${inventory.trackedFileCount} tracked files.`, provenance }),
    store.addClaim({ projectId: project.id, snapshotId: snapshot.id, kind: "assumption", summary: "Authentication and authorization model require recon validation.", provenance: { ...provenance, confidence: 0.2 } })
  ];
  const coverage = ["access-control", "authentication", "injection", "security-misconfiguration", "supply-chain"].map((attackClass) => store.upsertCoverage({ projectId: project.id, snapshotId: snapshot.id, area: "repository", attackClass, depth: "none", sourceRevision: inventory.revision, proofGaps: ["No specialist review has completed."], evidenceIds: [inventoryArtifact.id] }));
  const semgrepConfig = resolve(new URL("../../rules/semgrep/baseline.yml", import.meta.url).pathname);
  const tasks = initialTasks.map(([kind, inputs]) => store.createTask({ projectId: project.id, snapshotId: snapshot.id, kind, priority: calculatePriority(inputs), scope: { repository_root: repositoryRoot, source_revision: inventory.revision, policy: "default-scope", ...(kind === "semgrep-sast" ? { semgrep_config: semgrepConfig } : {}) } }));
  return { project, snapshot, inventory, artifacts: [inventoryArtifact, threatModelArtifact], threatModel: persistedThreatModel, scopePolicy: persistedScopePolicy, facts, coverage, tasks };
}
