# Runtime validation contract

Runtime validation is disabled by default. Before executing a request, require all of the following:

1. The target is a configured primary target.
2. Active testing is enabled in policy.
3. Explicit approval is recorded.
4. Test identities and objects are supplied.
5. The request uses GET, HEAD, or OPTIONS; any other method needs a separate policy opt-in.

Each candidate has a control case and proof case. Capture redacted request/response evidence and promote a hypothesis only after the validator establishes that the specified invariant is broken. A blocked environment remains `VALIDATION_BLOCKED`; it is never reported as a confirmed vulnerability.
