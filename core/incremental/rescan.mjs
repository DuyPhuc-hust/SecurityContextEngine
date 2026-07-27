import { resolve } from "node:path";
import { changedGitPaths, inventoryGitRepository } from "../../adapters/git/inventory.mjs";
import { writeJsonArtifact } from "../artifacts/json-artifact.mjs";
import { calculatePriority } from "../scheduler/priority.mjs";

/** Schedule only the closure affected by a Git revision change. */
export async function scheduleIncrementalRescan({ store, stateDirectory, projectId, repositoryPath }) {
  const previous = store.latestSnapshot(projectId);
  if (!previous) throw new Error("Create an initial scan before scheduling an incremental rescan.");
  const repositoryRoot = resolve(repositoryPath);
  const inventory = await inventoryGitRepository(repositoryRoot);
  if (inventory.revision === previous.revision) return { changed: false, previous, snapshot: previous, changedPaths: [], tasks: [] };
  const changedPaths = await changedGitPaths(repositoryRoot, previous.revision, inventory.revision);
  const snapshot = store.createSnapshot(projectId, inventory.revision);
  const artifactFile = writeJsonArtifact({ stateDirectory, projectId, snapshotId: snapshot.id, name: "git-impact", value: { from: previous.revision, to: inventory.revision, changed_paths: changedPaths } });
  const artifact = store.addArtifact({ projectId, snapshotId: snapshot.id, kind: "git-impact", uri: artifactFile.uri, contentHash: artifactFile.contentHash });
  const staleCoverage = store.markCoverageStale(previous.id);
  const scope = { repository_root: repositoryRoot, source_revision: inventory.revision, previous_revision: previous.revision, changed_paths: changedPaths, impact_artifact_id: artifact.id };
  const tasks = [
    store.createTask({ projectId, snapshotId: snapshot.id, kind: "impact-analysis", priority: calculatePriority({ expectedRisk: 1, expectedInformationGain: 1, coverageGap: 1, estimatedCost: 0.4 }), scope }),
    store.createTask({ projectId, snapshotId: snapshot.id, kind: "recon-diff", priority: calculatePriority({ expectedRisk: 0.8, expectedInformationGain: 0.7, coverageGap: 1, estimatedCost: 0.5 }), scope })
  ];
  return { changed: true, previous, snapshot, changedPaths, artifact, staleCoverage, tasks };
}
