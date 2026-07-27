export function createInitialThreatModel({ repositoryRoot, inventory }) {
  return {
    version: 1,
    status: "draft",
    system_purpose: "Unknown; human review required.",
    assets: ["source code", "configuration", "dependencies", "credentials and secrets", "user data"],
    entry_points: [],
    untrusted_inputs: ["HTTP/API inputs (if exposed)", "configuration", "dependency updates", "file inputs"],
    attacker_identities: ["unauthenticated external actor", "authenticated low-privilege user", "compromised integration"],
    trust_boundaries: ["repository source to build pipeline", "application boundary to external callers", "application boundary to dependencies"],
    authentication_assumptions: ["Unknown; must be verified during recon."],
    authorization_model: "Unknown; must be verified during recon.",
    sensitive_operations: [],
    sensitive_data_paths: [],
    deployment_assumptions: ["Environment configuration is not yet observed."],
    invariants: [
      "An actor must not access an object outside its authorized tenant or ownership boundary.",
      "Untrusted input must not reach a dangerous sink without appropriate validation or encoding.",
      "Secrets and sensitive data must not be exposed to unauthorized actors."
    ],
    priority_areas: ["access control", "authentication", "injection", "security misconfiguration", "supply chain"],
    exclusions: ["Active runtime testing until a primary target and approval are supplied."],
    provenance: {
      origin: "deterministic-tool",
      source_revision: inventory.revision,
      extractor_version: "scan-init/v1",
      created_at: new Date().toISOString(),
      repository_root: repositoryRoot,
      inventory_artifact: inventory
    }
  };
}
