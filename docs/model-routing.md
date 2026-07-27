# Model-independent routing

Provider integrations expose capabilities, not hardcoded workflow names. The router chooses a compatible provider using task tier, structured-output support, estimated cost, and latency.

- Fact extraction: cheap + structured output.
- Cross-region hypothesis linking: medium tier.
- High-impact reporting: strong tier.
- Validation: exclude the discovery provider when an independent eligible provider exists.

Every provider call must record provider/model, task type, prompt/schema version, input/output tokens, cost, latency, cache status, and outcome in `agent_runs`.
