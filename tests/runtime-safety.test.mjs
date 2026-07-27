import test from "node:test";
import assert from "node:assert/strict";
import { ScopeViolationError } from "../core/scope/enforcement.mjs";
import { runControlProofValidation } from "../agents/validator/runtime-control-proof.mjs";

const policy = { activeTestingAllowed: true, primaryTargets: ["https://app.test"], requireApprovalForActiveTesting: true, allowNonDestructiveWriteMethods: false };
const request = { method: "GET", url: "https://app.test/resource", headers: { Authorization: "secret" } };

test("runtime harness redacts evidence and requires approval", async () => {
  const result = await runControlProofValidation({ policy, approved: true, target: "https://app.test", controlCase: { request, expect: (response) => response.status === 200 }, proofCase: { request, expect: (response) => response.status === 200 }, send: async () => ({ status: 200, headers: {}, body: "ok" }) });
  assert.equal(result.status, "proof-observed");
  assert.equal(result.control.evidence.request.headers.Authorization, "[REDACTED]");
  await assert.rejects(() => runControlProofValidation({ policy, approved: false, target: "https://app.test", controlCase: { request, expect: () => true }, proofCase: { request, expect: () => true }, send: async () => ({ status: 200 }) }), ScopeViolationError);
});
