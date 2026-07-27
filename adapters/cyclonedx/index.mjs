import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { writeJsonArtifact } from "../../core/artifacts/json-artifact.mjs";

const componentLabel = (component) => component.purl ?? `${component.group ? `${component.group}/` : ""}${component.name}@${component.version ?? "unknown"}`;

export function normalizeCycloneDx(document) {
  if (document?.bomFormat !== "CycloneDX" || !Array.isArray(document.components)) throw new Error("Expected CycloneDX JSON BOM with components array.");
  const components = document.components.map((component) => ({ ref: component["bom-ref"] ?? component.purl ?? componentLabel(component), label: componentLabel(component), name: component.name, version: component.version ?? null, type: component.type ?? "library", purl: component.purl ?? null, licenses: component.licenses ?? [] }));
  const dependencies = (document.dependencies ?? []).flatMap((entry) => (entry.dependsOn ?? []).map((to) => ({ from: entry.ref, to })));
  const vulnerabilities = (document.vulnerabilities ?? []).map((vulnerability) => ({
    id: vulnerability.id ?? "unknown-vulnerability",
    severity: vulnerability.ratings?.[0]?.severity ?? null,
    message: vulnerability.description ?? vulnerability.detail ?? vulnerability.id ?? "CycloneDX vulnerability entry",
    affected: vulnerability.affects?.map((entry) => entry.ref) ?? []
  }));
  return { components, dependencies, vulnerabilities };
}

export function importCycloneDx({ store, stateDirectory, projectId, snapshotId, document }) {
  const artifactFile = writeJsonArtifact({ stateDirectory, projectId, snapshotId, name: "cyclonedx-sbom", value: document });
  const artifact = store.addArtifact({ projectId, snapshotId, kind: "cyclonedx-sbom", uri: artifactFile.uri, contentHash: artifactFile.contentHash });
  const normalized = normalizeCycloneDx(document);
  const snapshot = store.getSnapshot(snapshotId);
  if (!snapshot) throw new Error(`Snapshot not found: ${snapshotId}`);
  const provenance = { origin: "deterministic-tool", artifact_ids: [artifact.id], source_revision: snapshot.revision, extractor_version: "cyclonedx-import/v1", confidence: 0.9, created_at: new Date().toISOString(), stale: false };
  const nodes = new Map(normalized.components.map((component) => [component.ref, store.addContextNode({ projectId, snapshotId, kind: "dependency", label: component.label, attributes: component, provenance })]));
  const edges = normalized.dependencies.flatMap((dependency) => {
    const from = nodes.get(dependency.from);
    const to = nodes.get(dependency.to);
    return from && to ? [store.addContextEdge({ projectId, snapshotId, fromNodeId: from.id, toNodeId: to.id, kind: "DEPENDS_ON", provenance })] : [];
  });
  const signals = normalized.vulnerabilities.flatMap((vulnerability) => vulnerability.affected.length ? vulnerability.affected.map((ref) => store.addSignal({ projectId, snapshotId, tool: "cyclonedx", ruleId: vulnerability.id, severity: vulnerability.severity, message: vulnerability.message, location: { dependency: ref }, artifactId: artifact.id })) : [store.addSignal({ projectId, snapshotId, tool: "cyclonedx", ruleId: vulnerability.id, severity: vulnerability.severity, message: vulnerability.message, location: {}, artifactId: artifact.id })]);
  const fact = store.addClaim({ projectId, snapshotId, kind: "fact", summary: `Imported ${nodes.size} dependencies and ${edges.length} dependency relationships from CycloneDX.`, provenance });
  return { artifact, normalized, graph: { nodes: nodes.size, edges: edges.length }, signals, fact };
}

export function importCycloneDxFile({ store, stateDirectory, projectId, snapshotId, path }) {
  return importCycloneDx({ store, stateDirectory, projectId, snapshotId, document: JSON.parse(readFileSync(resolve(path), "utf8")) });
}
