# MVP scope

The first executable slice targets one TypeScript/Node repository in whitebox mode. `scan:init` now creates a Git snapshot, inventory artifact, draft threat model, provenance-backed facts, coverage cells, and persistent Recon/Hunt tasks. Route/function/auth/source/sink extraction and normalized Semgrep/Trivy signals remain the next implementation slice.

Active runtime testing is disabled by default. It requires an approved primary target, isolated environment, test identities, and non-destructive control/proof cases.
