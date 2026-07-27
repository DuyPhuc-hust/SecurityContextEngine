export interface ScopePolicy {
  targetMode: "whitebox" | "blackbox" | "hybrid";
  primaryTargets: string[];
  relatedTargetsPassiveOnly: boolean;
  activeTestingAllowed: boolean;
  requireApprovalForActiveTesting: boolean;
}

export function mayActivelyTest(policy: ScopePolicy, approved: boolean): boolean {
  return policy.activeTestingAllowed && (!policy.requireApprovalForActiveTesting || approved);
}
