import test from "node:test";
import assert from "node:assert/strict";
import { selectProvider, routeValidation } from "../core/scheduler/model-router.mjs";

const providers = [
  { id: "cheap", capabilities: { tier: "cheap", structuredOutput: true }, estimatedCost: 1 },
  { id: "medium-a", capabilities: { tier: "medium", structuredOutput: true }, estimatedCost: 2 },
  { id: "medium-b", capabilities: { tier: "medium", structuredOutput: true }, estimatedCost: 3 }
];

test("routes fact extraction by cost and validation independently", () => {
  assert.equal(selectProvider({ providers, taskType: "fact-extraction" }).id, "cheap");
  assert.equal(routeValidation({ providers, discoveryProviderId: "medium-a" }).id, "medium-b");
});
