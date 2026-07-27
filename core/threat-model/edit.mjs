import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { writeJsonArtifact } from "../artifacts/json-artifact.mjs";

export function updateThreatModelFromFile({ store, stateDirectory, projectId, snapshotId, path, status = "draft" }) {
  const document = JSON.parse(readFileSync(resolve(path), "utf8"));
  const previous = store.getLatestThreatModel(projectId, snapshotId);
  const nextVersion = (previous?.version ?? 0) + 1;
  const file = writeJsonArtifact({ stateDirectory, projectId, snapshotId, name: `threat-model-v${nextVersion}`, value: document });
  const artifact = store.addArtifact({ projectId, snapshotId, kind: "threat-model", uri: file.uri, contentHash: file.contentHash });
  const model = store.saveThreatModel({ projectId, snapshotId, document, status, artifactId: artifact.id });
  return { model, artifact };
}
