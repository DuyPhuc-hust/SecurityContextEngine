import { existsSync, readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";
import { writeJsonArtifact } from "../../core/artifacts/json-artifact.mjs";

const execFileAsync = promisify(execFile);
const projectRoot = resolve(new URL("../..", import.meta.url).pathname);
const bundledBinary = resolve(projectRoot, ".tools/bin/semgrep");
const bundledPythonPackages = resolve(projectRoot, ".tools/lib/python3.10/site-packages");

export function semgrepStatus() {
  const executable = process.env.SEMGREP_BIN || bundledBinary;
  return { executable, available: existsSync(executable), configuredPythonPath: existsSync(bundledPythonPackages) ? bundledPythonPackages : null };
}

export async function runSemgrep({ targetPath, configPath, executable = semgrepStatus().executable }) {
  if (!existsSync(executable)) throw new Error("Semgrep executable unavailable. Set SEMGREP_BIN or install a compatible Semgrep binary.");
  const environment = { ...process.env };
  if (existsSync(bundledPythonPackages)) environment.PYTHONPATH = [bundledPythonPackages, environment.PYTHONPATH].filter(Boolean).join(":");
  const { stdout } = await execFileAsync(executable, ["scan", "--json", "--config", resolve(configPath), resolve(targetPath)], { env: environment, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(stdout);
}

export function normalizeSemgrep(output) {
  if (!Array.isArray(output?.results)) throw new Error("Expected Semgrep JSON with a results array.");
  return output.results.map((result) => ({
    tool: "semgrep",
    ruleId: result.check_id,
    severity: result.extra?.severity ?? result.extra?.metadata?.severity ?? null,
    message: result.extra?.message ?? "Semgrep signal",
    location: {
      path: result.path,
      start: result.start ? { line: result.start.line, column: result.start.col } : null,
      end: result.end ? { line: result.end.line, column: result.end.col } : null,
      metadata: result.extra?.metadata ?? {}
    }
  }));
}

export function importSemgrepOutput({ store, stateDirectory, projectId, snapshotId, outputPath }) {
  const raw = JSON.parse(readFileSync(resolve(outputPath), "utf8"));
  return importSemgrepDocument({ store, stateDirectory, projectId, snapshotId, raw });
}

export function importSemgrepDocument({ store, stateDirectory, projectId, snapshotId, raw }) {
  const artifactFile = writeJsonArtifact({ stateDirectory, projectId, snapshotId, name: "semgrep-output", value: raw });
  const artifact = store.addArtifact({ projectId, snapshotId, kind: "semgrep-output", uri: artifactFile.uri, contentHash: artifactFile.contentHash });
  const signals = normalizeSemgrep(raw).map((signal) => store.addSignal({ projectId, snapshotId, ...signal, artifactId: artifact.id }));
  return { artifact, signals };
}
