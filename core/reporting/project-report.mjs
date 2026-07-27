export function buildProjectSummary(store, projectId) {
  const project = store.getProject(projectId);
  if (!project) throw new Error(`Project not found: ${projectId}`);
  const tasks = store.listTasks(projectId);
  const coverage = store.listCoverage(projectId);
  const signals = store.listSignals(projectId);
  const findings = store.listFindings(projectId);
  const runs = store.listAgentRuns(projectId);
  const taskCounts = Object.groupBy(tasks, ({ state }) => state);
  const findingCounts = Object.groupBy(findings, ({ state }) => state);
  return {
    project,
    tasks: Object.fromEntries(Object.entries(taskCounts).map(([state, values]) => [state, values.length])),
    coverage: {
      total: coverage.length,
      deep: coverage.filter(({ depth }) => depth === "deep").length,
      incomplete: coverage.filter(({ depth, stale }) => depth !== "deep" || stale === 1).map(({ area, attack_class, depth, proof_gaps_json, stale }) => ({ area, attackClass: attack_class, depth, stale: stale === 1, proofGaps: JSON.parse(proof_gaps_json) }))
    },
    signals: { total: signals.length, byTool: Object.fromEntries(Object.entries(Object.groupBy(signals, ({ tool }) => tool)).map(([tool, values]) => [tool, values.length])) },
    findings: {
      total: findings.length,
      byState: Object.fromEntries(Object.entries(findingCounts).map(([state, values]) => [state, values.length])),
      developerReady: findings.filter(({ state }) => ["CONFIRMED", "ACCEPTED", "RISK_ACCEPTED"].includes(state)).map((finding) => ({
        id: finding.id,
        title: finding.title,
        state: finding.state,
        details: store.getFindingDetails(finding.id),
        feedback: store.listFeedback(finding.id)
      }))
    },
    execution: { runs: runs.length, inputTokens: runs.reduce((total, run) => total + run.input_tokens, 0), outputTokens: runs.reduce((total, run) => total + run.output_tokens, 0), cost: runs.reduce((total, run) => total + run.cost, 0), latencyMs: runs.reduce((total, run) => total + (run.latency_ms ?? 0), 0) }
  };
}

export function renderProjectMarkdown(summary) {
  const confirmed = summary.findings.byState.CONFIRMED ?? 0;
  const coverageLines = summary.coverage.incomplete.length
    ? summary.coverage.incomplete.map((item) => `- ${item.area} × ${item.attackClass}: ${item.depth}${item.stale ? ", stale" : ""}; proof gaps: ${item.proofGaps.join("; ") || "none recorded"}`).join("\n")
    : "- No recorded coverage gaps.";
  return `# Security Context Report: ${summary.project.name}

## Result

${confirmed ? `${confirmed} confirmed finding(s) exist in the stored scope.` : "No confirmed findings in the recorded scope and coverage."}

## Tasks

${Object.entries(summary.tasks).map(([state, count]) => `- ${state}: ${count}`).join("\n") || "- No tasks."}

## Signals and findings

- Signals: ${summary.signals.total}
- Findings: ${summary.findings.total}
- Finding states: ${Object.entries(summary.findings.byState).map(([state, count]) => `${state}=${count}`).join(", ") || "none"}

## Coverage and proof gaps

${coverageLines}

## Execution accounting

- Agent/tool runs: ${summary.execution.runs}
- Tokens: ${summary.execution.inputTokens} input / ${summary.execution.outputTokens} output
- Recorded cost: ${summary.execution.cost}
- Recorded latency: ${summary.execution.latencyMs} ms
`;
}
