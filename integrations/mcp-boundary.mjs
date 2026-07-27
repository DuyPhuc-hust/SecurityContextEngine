// Transport-neutral MCP/Agent Skill boundary. A host can expose these tools through
// its MCP server without giving the model direct database or filesystem access.
export function createSecurityContextTools({ store }) {
  return {
    "security_context.report": ({ projectId }) => ({ kind: "report", value: store.listFindings(projectId) }),
    "security_context.coverage": ({ projectId }) => ({ kind: "coverage", value: store.listCoverage(projectId) }),
    "security_context.feedback": ({ findingId, decision, reviewer, reason }) => store.recordDeveloperFeedback({ findingId, decision, reviewer, reason })
  };
}

export function invokeSecurityContextTool(tools, name, input = {}) {
  if (!tools[name]) throw new Error(`Unknown security context tool: ${name}`);
  return tools[name](input);
}
