import { extractTypeScriptInventory } from "../../analyzers/whitebox/typescript-inventory.mjs";
import { writeJsonArtifact } from "../artifacts/json-artifact.mjs";
import { loadOrExtractInventory } from "../cache/content-cache.mjs";

export async function ingestTypeScriptInventory({ store, stateDirectory, projectId, snapshotId, repositoryPath }) {
  const snapshot = store.getSnapshot(snapshotId);
  if (!snapshot) throw new Error(`Snapshot not found: ${snapshotId}`);
  const cached = await loadOrExtractInventory({ store, projectId, sourceRevision: snapshot.revision, extractorVersion: "typescript-inventory/v1", extract: () => extractTypeScriptInventory(repositoryPath) });
  const inventory = cached.inventory;
  const artifactFile = writeJsonArtifact({ stateDirectory, projectId, snapshotId, name: "typescript-inventory", value: inventory });
  const artifact = store.addArtifact({ projectId, snapshotId, kind: "typescript-inventory", uri: artifactFile.uri, contentHash: artifactFile.contentHash });
  const provenance = { origin: "deterministic-tool", artifact_ids: [artifact.id], source_revision: snapshot.revision, extractor_version: inventory.version, confidence: 0.85, created_at: new Date().toISOString(), stale: false };
  const facts = [
    store.addClaim({ projectId, snapshotId, kind: "fact", summary: `Extracted ${inventory.symbols.length} symbols and ${inventory.routes.length} route candidates from TypeScript/JavaScript.`, provenance }),
    store.addClaim({ projectId, snapshotId, kind: "fact", summary: `Identified ${inventory.sources.length} input sources, ${inventory.sinks.length} potential sinks, and ${inventory.controls.length} candidate security controls.`, provenance })
  ];
  const nodeFor = new Map();
  const addNode = (key, kind, label, attributes = {}) => {
    if (!nodeFor.has(key)) nodeFor.set(key, store.addContextNode({ projectId, snapshotId, kind, label, attributes, provenance }));
    return nodeFor.get(key);
  };
  const fileNodes = new Map(inventory.files.map((file) => [file.path, addNode(`file:${file.path}`, "file", file.path, file)]));
  for (const symbol of inventory.symbols) addNode(`symbol:${symbol.id}`, "symbol", symbol.name, symbol);
  for (const route of inventory.routes) addNode(`route:${route.method}:${route.path}`, "route", `${route.method} ${route.path}`, route);
  for (const source of inventory.sources) addNode(`source:${source.file}:${source.line}:${source.expression}`, "source", source.expression, source);
  for (const sink of inventory.sinks) addNode(`sink:${sink.file}:${sink.line}:${sink.name}`, "sink", sink.name, sink);
  for (const control of inventory.controls) addNode(`control:${control.file}:${control.line}:${control.name}`, control.kind, control.name, control);
  const edges = [];
  for (const item of inventory.imports) {
    const module = addNode(`module:${item.module}`, "module", item.module, { module: item.module });
    edges.push(store.addContextEdge({ projectId, snapshotId, fromNodeId: fileNodes.get(item.file).id, toNodeId: module.id, kind: "IMPORTS", attributes: { line: item.line }, provenance }));
  }
  for (const route of inventory.routes) {
    const routeNode = nodeFor.get(`route:${route.method}:${route.path}`);
    edges.push(store.addContextEdge({ projectId, snapshotId, fromNodeId: fileNodes.get(route.file).id, toNodeId: routeNode.id, kind: "EXPOSES", attributes: { line: route.line }, provenance }));
  }
  return { inventory, artifact, facts, graph: { nodes: nodeFor.size, edges: edges.length }, cacheHit: cached.cacheHit };
}
