/** Retrieval policy: exact graph matches precede lexical fallback. */
export function retrieveContext(store, { projectId, snapshotId, query, limit = 20 }) {
  const matches = store.searchContextNodes({ projectId, snapshotId, query, limit });
  return {
    strategy: "exact-label-then-lexical",
    query,
    matches: matches.map((node) => ({ ...node, attributes: JSON.parse(node.attributes_json), provenance: JSON.parse(node.provenance_json) }))
  };
}
