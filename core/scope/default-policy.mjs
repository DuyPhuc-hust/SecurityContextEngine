export function createDefaultScopePolicy() {
  return {
    version: 1,
    target_mode: "whitebox",
    primary_targets: [],
    related_targets: { discovery: "passive-only", active_testing: false },
    cross_domain: { record_relationships: true, follow_redirects: "same-scope-only" },
    active_testing: false,
    require_approval_for_active_testing: true,
    allowed_methods: ["GET", "HEAD", "OPTIONS"],
    redact_secrets: true,
    redact_pii: true
  };
}

export function toRuntimePolicy(document) {
  return {
    activeTestingAllowed: document.active_testing,
    primaryTargets: document.primary_targets,
    requireApprovalForActiveTesting: document.require_approval_for_active_testing,
    allowNonDestructiveWriteMethods: document.allowed_methods?.some((method) => !["GET", "HEAD", "OPTIONS"].includes(method)) ?? false
  };
}
