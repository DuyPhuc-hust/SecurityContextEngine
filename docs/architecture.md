# Architecture decisions

`skills/security-hunt` parses requests and calls the engine; it never owns durable state. Core contracts can be exposed through a CLI or MCP server.

```text
Agent Skill / CLI / MCP
          |
Scope & policy -> ingestion -> context store -> scheduler
                                          |          |
                                    discovery lanes  v
                                     -> hypotheses -> independent validation
                                                          |
                                                    evidence / finding / patch
```

## Data vocabulary

- **Observation:** observed behavior.
- **Fact:** provenance-backed source/runtime statement.
- **Assumption:** unverified assertion.
- **Invariant:** required security property.
- **Hypothesis:** unconfirmed candidate.
- **Finding:** a candidate meeting the evidence threshold.
- **Evidence:** immutable source, request/response, log, trace, test, or artifact reference.

All claims reference snapshot/revision and provenance. Missing provenance downgrades a statement to an assumption or hypothesis.

## Finding lifecycle

`SIGNAL → HYPOTHESIS → UNDER_REVIEW → VALIDATION_PLANNED → PARTIALLY_VALIDATED | VALIDATION_BLOCKED | REJECTED | CONFIRMED → ACCEPTED → PATCH_PROPOSED → FIX_VERIFIED → CLOSED`

Source, dependency, policy, model/rule, or runtime-assumption changes can mark context stale and reopen a finding.

## Remediation rule

Only a human-accepted confirmed finding receives remediation. Create one remediation task per accepted finding; it must reproduce, minimally patch, add regression coverage, re-run proof/control cases, check nearby bypasses, and verify the fix before closure.
