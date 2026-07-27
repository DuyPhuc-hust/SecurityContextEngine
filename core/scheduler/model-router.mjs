const taskRequirements = {
  "fact-extraction": { tier: "cheap", structuredOutput: true },
  "hypothesis-linking": { tier: "medium", structuredOutput: true },
  "access-control-hunt": { tier: "medium", structuredOutput: true },
  "auth-hunt": { tier: "medium", structuredOutput: true },
  "injection-hunt": { tier: "medium", structuredOutput: true },
  "validate-access-control": { tier: "medium", structuredOutput: true, independent: true },
  "report": { tier: "strong", structuredOutput: false }
};

const tierWeight = { cheap: 1, medium: 2, strong: 3 };

export function selectProvider({ providers, taskType, excludeProviderIds = [] }) {
  const requirement = taskRequirements[taskType] ?? { tier: "medium", structuredOutput: true };
  const excluded = new Set(excludeProviderIds);
  const candidates = providers.filter((provider) => !excluded.has(provider.id) && tierWeight[provider.capabilities.tier] >= tierWeight[requirement.tier] && (!requirement.structuredOutput || provider.capabilities.structuredOutput));
  if (!candidates.length) throw new Error(`No provider satisfies routing requirements for ${taskType}.`);
  return candidates.sort((left, right) => (left.estimatedCost ?? Infinity) - (right.estimatedCost ?? Infinity) || (left.expectedLatencyMs ?? Infinity) - (right.expectedLatencyMs ?? Infinity))[0];
}

export function routeValidation({ providers, discoveryProviderId, taskType = "validate-access-control" }) {
  return selectProvider({ providers, taskType, excludeProviderIds: discoveryProviderId ? [discoveryProviderId] : [] });
}
