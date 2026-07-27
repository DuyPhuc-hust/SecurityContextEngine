import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const validationPattern = /validat|saniti|escape|safeparse|schema/i;

export function huntInjection({ store, projectId, snapshotId }) {
  const artifact = store.latestArtifact({ projectId, snapshotId, kind: "typescript-inventory" });
  if (!artifact) throw new Error("Run whitebox:typescript for this snapshot before injection hunting.");
  const inventory = JSON.parse(readFileSync(resolve(process.cwd(), artifact.uri), "utf8"));
  const sourcesByFile = new Set(inventory.sources.filter((source) => source.kind === "http-input").map((source) => source.file));
  const hypotheses = inventory.sinks.flatMap((sink) => {
    if (!sourcesByFile.has(sink.file)) return [];
    const routeWithValidation = inventory.routes.some((route) => route.file === sink.file && route.middleware.some((item) => validationPattern.test(item)));
    if (routeWithValidation) return [];
    return [store.createHypothesis({
      projectId, snapshotId, fingerprint: `injection:${sink.file}:${sink.line}:${sink.name}`,
      title: `Possible untrusted-input reachability to ${sink.name} at ${sink.file}:${sink.line}`,
      attackClass: "injection",
      securityInvariant: "Untrusted input must not reach dangerous execution or query sinks without context-appropriate validation or encoding.",
      rank: 0.65,
      evidenceIds: [artifact.id],
      rationale: `The file contains HTTP-derived input and a ${sink.name} sink; no route-level validation control was recognized. This is a data-flow candidate, not proof that input reaches the sink.`
    })];
  });
  return { artifact, hypotheses, sources: inventory.sources.length, sinks: inventory.sinks.length };
}
