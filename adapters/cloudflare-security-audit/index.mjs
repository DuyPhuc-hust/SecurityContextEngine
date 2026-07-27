import { existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(new URL("../..", import.meta.url).pathname);

export const cloudflareBaseline = Object.freeze({
  id: "cloudflare-security-audit-skill",
  root: resolve(repositoryRoot, "external/cloudflare-security-audit-skill"),
  skillRoot: resolve(repositoryRoot, "external/cloudflare-security-audit-skill/skills/security-audit"),
  license: "MIT",
  revision: "8bac42001ddd90a4dcd8d5a5045199283a8eba75"
});

export function baselineStatus() {
  const validator = resolve(cloudflareBaseline.skillRoot, "validate-findings.cjs");
  return {
    ...cloudflareBaseline,
    available: existsSync(cloudflareBaseline.skillRoot),
    validatorAvailable: existsSync(validator)
  };
}

/** Validate a baseline findings.json without changing upstream files. */
export async function validateCloudflareFindings(findingsPath) {
  const validator = resolve(cloudflareBaseline.skillRoot, "validate-findings.cjs");
  if (!existsSync(validator)) throw new Error("Cloudflare baseline validator is unavailable; restore the external baseline first.");
  const { stdout, stderr } = await execFileAsync(process.execPath, [validator, resolve(findingsPath)]);
  return { stdout, stderr };
}
