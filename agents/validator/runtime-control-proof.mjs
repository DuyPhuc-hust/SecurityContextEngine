import { createHash } from "node:crypto";
import { assertRuntimeRequestAllowed } from "../../core/scope/enforcement.mjs";

function redactHeaders(headers = {}) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => (/authorization|cookie|token|secret/i.test(key) ? [key, "[REDACTED]"] : [key, value])));
}

function evidenceFor(request, response) {
  const body = typeof response.body === "string" ? response.body : JSON.stringify(response.body ?? null);
  return {
    request: { method: request.method, url: request.url, headers: redactHeaders(request.headers) },
    response: { status: response.status, headers: redactHeaders(response.headers), body_hash: createHash("sha256").update(body).digest("hex") }
  };
}

/**
 * Execute a non-destructive control/proof pair only after scope enforcement.
 * `send` is injected so production HTTP execution remains an adapter concern.
 */
export async function runControlProofValidation({ policy, approved, target, controlCase, proofCase, send }) {
  for (const request of [controlCase.request, proofCase.request]) assertRuntimeRequestAllowed({ policy, target, approved, request });
  const controlResponse = await send(controlCase.request);
  const proofResponse = await send(proofCase.request);
  const controlPassed = controlCase.expect(controlResponse);
  const proofPassed = proofCase.expect(proofResponse);
  return {
    status: controlPassed && proofPassed ? "proof-observed" : "not-confirmed",
    control: { passed: controlPassed, evidence: evidenceFor(controlCase.request, controlResponse) },
    proof: { passed: proofPassed, evidence: evidenceFor(proofCase.request, proofResponse) }
  };
}
