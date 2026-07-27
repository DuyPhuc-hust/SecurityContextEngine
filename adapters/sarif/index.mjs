import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { writeJsonArtifact } from "../../core/artifacts/json-artifact.mjs";

export function normalizeSarif(document) {
  if (!Array.isArray(document?.runs)) throw new Error("Expected SARIF document with runs array.");
  return document.runs.flatMap((run) => {
    const tool = run.tool?.driver?.name ?? "sarif";
    const rules = new Map((run.tool?.driver?.rules ?? []).map((rule) => [rule.id, rule]));
    return (run.results ?? []).map((result) => {
      const location = result.locations?.[0]?.physicalLocation;
      const rule = rules.get(result.ruleId);
      return {
        tool,
        ruleId: result.ruleId ?? "unknown",
        severity: result.level ?? rule?.defaultConfiguration?.level ?? null,
        message: result.message?.text ?? result.message?.markdown ?? "SARIF signal",
        location: {
          path: location?.artifactLocation?.uri ?? null,
          start: location?.region?.startLine ? { line: location.region.startLine, column: location.region.startColumn ?? null } : null,
          end: location?.region?.endLine ? { line: location.region.endLine, column: location.region.endColumn ?? null } : null,
          properties: result.properties ?? {}
        }
      };
    });
  });
}

export function importSarif({ store, stateDirectory, projectId, snapshotId, document }) {
  const artifactFile = writeJsonArtifact({ stateDirectory, projectId, snapshotId, name: "sarif-output", value: document });
  const artifact = store.addArtifact({ projectId, snapshotId, kind: "sarif-output", uri: artifactFile.uri, contentHash: artifactFile.contentHash });
  const signals = normalizeSarif(document).map((signal) => store.addSignal({ projectId, snapshotId, ...signal, artifactId: artifact.id }));
  return { artifact, signals };
}

export function importSarifFile({ store, stateDirectory, projectId, snapshotId, path }) {
  return importSarif({ store, stateDirectory, projectId, snapshotId, document: JSON.parse(readFileSync(resolve(path), "utf8")) });
}
