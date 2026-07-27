import { createSecurityContextAgent } from "./agent-kit.mjs";

// A host agent can call these methods from its own tool loop.
const security = createSecurityContextAgent({ dbPath: ".security-context/context.db" });
const run = await security.initialize({ repositoryPath: process.cwd(), projectName: "embedded-target" });
await security.runDiscovery({ projectId: run.project.id, workerId: "host-agent" });
console.log(JSON.stringify(security.report(run.project.id), null, 2));
security.close();
