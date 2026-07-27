import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { SqliteStore } from "../core/state/sqlite-store.mjs";
import { initializeScan } from "../core/scan/initialize.mjs";
import { claimAndExecuteDeterministic } from "../core/scheduler/deterministic-worker.mjs";
import { buildProjectSummary } from "../core/reporting/project-report.mjs";

const benchmarkName = process.argv[2] ?? "whitebox-basic";
const benchmarkRoot = resolve("benchmarks", benchmarkName);
const expected = JSON.parse(readFileSync(join(benchmarkRoot, "expected.json"), "utf8"));
const workspace = mkdtempSync(join(tmpdir(), `sce-benchmark-${benchmarkName}-`));
const stateDirectory = join(workspace, "state");

try {
  cpSync(join(benchmarkRoot, "app.ts"), join(workspace, "app.ts"));
  execFileSync("git", ["init", "-q", workspace]);
  execFileSync("git", ["-C", workspace, "add", "app.ts"]);
  execFileSync("git", ["-C", workspace, "-c", "user.name=Benchmark", "-c", "user.email=benchmark@example.invalid", "commit", "-qm", "seed"]);
  const store = new SqliteStore(join(stateDirectory, "context.db"));
  const initialized = await initializeScan({ store, stateDirectory, repositoryPath: workspace, projectName: `benchmark-${benchmarkName}` });
  for (let index = 0; index < 5; index += 1) await claimAndExecuteDeterministic({ store, stateDirectory, workerId: "benchmark-worker", projectId: initialized.project.id });
  const hypotheses = store.listHypotheses(initialized.project.id);
  const summary = buildProjectSummary(store, initialized.project.id);
  const actualClasses = [...new Set(hypotheses.map((hypothesis) => hypothesis.attack_class))].sort();
  const expectedClasses = [...expected.expected_hypothesis_attack_classes].sort();
  if (JSON.stringify(actualClasses) !== JSON.stringify(expectedClasses)) throw new Error(`Unexpected hypothesis classes: ${actualClasses.join(", ")}`);
  if (summary.coverage.incomplete.filter((entry) => entry.depth === "partial").length < expected.minimum_partial_coverage) throw new Error("Insufficient partial coverage");
  if (summary.findings.byState.CONFIRMED ?? 0 !== expected.expected_confirmed_findings) throw new Error("Unexpected confirmed findings");
  console.log(JSON.stringify({ benchmark: benchmarkName, hypotheses: hypotheses.length, hypothesisAttackClasses: actualClasses, partialCoverage: summary.coverage.incomplete.filter((entry) => entry.depth === "partial").length, confirmedFindings: summary.findings.byState.CONFIRMED ?? 0, taskStates: summary.tasks }, null, 2));
  store.close();
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
