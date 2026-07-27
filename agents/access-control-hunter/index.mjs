import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const objectMethods = new Set(["GET", "PUT", "PATCH", "DELETE"]);
const objectInvariant = "An actor must not access or modify an object outside its authorized tenant or ownership boundary.";

function loadInventory(store, projectId, snapshotId) {
  const artifact = store.latestArtifact({ projectId, snapshotId, kind: "typescript-inventory" });
  if (!artifact) throw new Error("Run whitebox:typescript for this snapshot before access-control hunting.");
  return { artifact, inventory: JSON.parse(readFileSync(resolve(process.cwd(), artifact.uri), "utf8")) };
}

/** Deterministic, conservative candidate generation. A candidate is never a confirmed finding. */
export function huntAccessControl({ store, projectId, snapshotId }) {
  const { artifact, inventory } = loadInventory(store, projectId, snapshotId);
  const sourceFiles = new Set(inventory.sources.filter((source) => source.kind === "http-input" && /\.(params|query)/.test(source.expression)).map((source) => source.file));
  const hypotheses = [];
  for (const route of inventory.routes) {
    const objectReference = /:[A-Za-z][A-Za-z0-9_]*/.test(route.path);
    const ownershipControl = route.middleware.some((item) => /authorize|ownership|tenant|permission|role/i.test(item));
    if (!objectMethods.has(route.method) || !objectReference || ownershipControl || !sourceFiles.has(route.file)) continue;
    const fingerprint = `access-control:${route.method}:${route.path}:${route.file}`;
    hypotheses.push(store.createHypothesis({
      projectId, snapshotId, fingerprint,
      title: `Possible object-level authorization gap at ${route.method} ${route.path}`,
      attackClass: "broken-access-control",
      securityInvariant: objectInvariant,
      rank: 0.6,
      evidenceIds: [artifact.id],
      rationale: `Route uses an object identifier and request-derived input in ${route.file}; no ownership/tenant/permission middleware was recognized. Authentication alone does not prove object-level authorization.`
    }));
  }
  return { artifact, hypotheses, scannedRoutes: inventory.routes.length };
}
