import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const sensitiveMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const authPattern = /auth|session|jwt|token|login/i;

export function huntAuthentication({ store, projectId, snapshotId }) {
  const artifact = store.latestArtifact({ projectId, snapshotId, kind: "typescript-inventory" });
  if (!artifact) throw new Error("Run whitebox:typescript for this snapshot before authentication hunting.");
  const inventory = JSON.parse(readFileSync(resolve(process.cwd(), artifact.uri), "utf8"));
  const hypotheses = inventory.routes.flatMap((route) => {
    const recognizedAuth = [...route.middleware, route.handler].some((item) => authPattern.test(item));
    if (!sensitiveMethods.has(route.method) || recognizedAuth) return [];
    return [store.createHypothesis({
      projectId, snapshotId, fingerprint: `authentication:${route.method}:${route.path}:${route.file}`,
      title: `Possible missing authentication at ${route.method} ${route.path}`,
      attackClass: "authentication",
      securityInvariant: "Sensitive operations must require an authenticated actor unless explicitly public.",
      rank: 0.55,
      evidenceIds: [artifact.id],
      rationale: `State-changing route ${route.method} ${route.path} has no route-level authentication control recognized by the deterministic extractor. Public-route intent must be reviewed before validation.`
    })];
  });
  return { artifact, hypotheses, scannedRoutes: inventory.routes.length };
}
