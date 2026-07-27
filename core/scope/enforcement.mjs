const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

export class ScopeViolationError extends Error {}

export function assertRuntimeRequestAllowed({ policy, target, approved, request }) {
  if (!policy.activeTestingAllowed) throw new ScopeViolationError("Active testing is disabled by policy.");
  if (!policy.primaryTargets.includes(target)) throw new ScopeViolationError("Target is not an approved primary target.");
  if (policy.requireApprovalForActiveTesting && !approved) throw new ScopeViolationError("Active testing requires explicit approval.");
  if (!safeMethods.has(request.method.toUpperCase()) && !policy.allowNonDestructiveWriteMethods) {
    throw new ScopeViolationError("Only GET, HEAD, and OPTIONS are allowed until non-destructive write methods are explicitly enabled.");
  }
}
