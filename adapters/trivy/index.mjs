import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { writeJsonArtifact } from "../../core/artifacts/json-artifact.mjs";

export function normalizeTrivy(document) {
  if (!Array.isArray(document?.Results)) throw new Error("Expected Trivy JSON document with Results array.");
  return document.Results.flatMap((result) => (result.Vulnerabilities ?? []).map((vulnerability) => ({
    tool: "trivy",
    ruleId: vulnerability.VulnerabilityID ?? "unknown-vulnerability",
    severity: vulnerability.Severity ?? null,
    message: vulnerability.Title || vulnerability.Description || vulnerability.VulnerabilityID || "Trivy vulnerability",
    location: {
      target: result.Target ?? null,
      class: result.Class ?? null,
      type: result.Type ?? null,
      package: vulnerability.PkgName ?? null,
      installedVersion: vulnerability.InstalledVersion ?? null,
      fixedVersion: vulnerability.FixedVersion ?? null,
      primaryUrl: vulnerability.PrimaryURL ?? null
    }
  })));
}

export function importTrivy({ store, stateDirectory, projectId, snapshotId, document }) {
  const artifactFile = writeJsonArtifact({ stateDirectory, projectId, snapshotId, name: "trivy-output", value: document });
  const artifact = store.addArtifact({ projectId, snapshotId, kind: "trivy-output", uri: artifactFile.uri, contentHash: artifactFile.contentHash });
  const signals = normalizeTrivy(document).map((signal) => store.addSignal({ projectId, snapshotId, ...signal, artifactId: artifact.id }));
  return { artifact, signals, normalizedCount: signals.length };
}

export function importTrivyFile({ store, stateDirectory, projectId, snapshotId, path }) {
  return importTrivy({ store, stateDirectory, projectId, snapshotId, document: JSON.parse(readFileSync(resolve(path), "utf8")) });
}
