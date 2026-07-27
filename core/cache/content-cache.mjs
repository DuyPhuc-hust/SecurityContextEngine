export function inventoryCacheKey(projectId, sourceRevision, extractorVersion = "typescript-inventory/v1") {
  return `inventory:${projectId}:${sourceRevision}:${extractorVersion}`;
}

export async function loadOrExtractInventory({ store, projectId, sourceRevision, extractorVersion, extract }) {
  const cacheKey = inventoryCacheKey(projectId, sourceRevision, extractorVersion);
  const cached = store.getCache(cacheKey);
  if (cached) return { inventory: cached.value, cacheHit: true };
  const inventory = await extract();
  store.setCache({ cacheKey, value: inventory, sourceRevision });
  return { inventory, cacheHit: false };
}
