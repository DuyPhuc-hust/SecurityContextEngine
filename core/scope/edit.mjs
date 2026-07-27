import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { writeJsonArtifact } from "../artifacts/json-artifact.mjs";

export function updateScopePolicyFromFile({ store, stateDirectory, projectId, snapshotId, path }) {
  const document = JSON.parse(readFileSync(resolve(path), "utf8"));
  const nextVersion = (store.getLatestScopePolicy(projectId, snapshotId)?.version ?? 0) + 1;
  const file = writeJsonArtifact({ stateDirectory, projectId, snapshotId, name: `scope-policy-v${nextVersion}`, value: document });
  const artifact = store.addArtifact({ projectId, snapshotId, kind: "scope-policy", uri: file.uri, contentHash: file.contentHash });
  return { policy: store.saveScopePolicy({ projectId, snapshotId, document, artifactId: artifact.id }), artifact };
}
