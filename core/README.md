# Core modules

- `state/`: SQLite persistence, snapshots, task leases, and resume/retry.
- `scheduler/`: deterministic queueing, budgets, rate limits, and model routing.
- `graph/`: nodes, edges, provenance, and context retrieval.
- `artifacts/`: immutable evidence storage and redaction.
- `cache/`: content-hash and semantic-summary cache.
- `findings/`: hypothesis deduplication and lifecycle transitions.
- `evidence/`: proof/control-case policy and evidence threshold checks.
- `coverage/`: area × attack-class coverage matrix and gapfill tasks.
- `incremental/`: dependency impact closure and stale-context invalidation.
