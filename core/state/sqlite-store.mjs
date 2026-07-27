import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { canTransition, findingStates } from "../findings/state-machine.mjs";

const now = () => new Date().toISOString();
const id = () => randomUUID();
const taskStates = new Set(["queued", "running", "blocked", "completed", "failed"]);

export class SqliteStore {
  constructor(path) {
    mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;");
    this.migrate();
  }

  migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), revision TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(project_id, revision));
      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        kind TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('queued','running','blocked','completed','failed')),
        scope_json TEXT NOT NULL, priority REAL NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
        worker_id TEXT, lease_expires_at TEXT, last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS artifacts (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        kind TEXT NOT NULL, uri TEXT NOT NULL, content_hash TEXT, redacted INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signals (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        tool TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT, message TEXT NOT NULL, location_json TEXT NOT NULL,
        artifact_id TEXT REFERENCES artifacts(id), created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        kind TEXT NOT NULL, summary TEXT NOT NULL, artifact_uri TEXT, source_revision TEXT NOT NULL,
        observed_json TEXT NOT NULL, redacted INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        kind TEXT NOT NULL, label TEXT NOT NULL, attributes_json TEXT NOT NULL, provenance_json TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(project_id, snapshot_id, kind, label)
      );
      CREATE TABLE IF NOT EXISTS edges (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        from_node_id TEXT NOT NULL REFERENCES nodes(id), to_node_id TEXT NOT NULL REFERENCES nodes(id), kind TEXT NOT NULL,
        attributes_json TEXT NOT NULL, provenance_json TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(project_id, snapshot_id, from_node_id, to_node_id, kind)
      );
      CREATE TABLE IF NOT EXISTS claims (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        kind TEXT NOT NULL CHECK(kind IN ('observation','fact','assumption','invariant','hypothesis')),
        summary TEXT NOT NULL, provenance_json TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        title TEXT NOT NULL, state TEXT NOT NULL, security_invariant TEXT NOT NULL, evidence_ids_json TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS finding_details (
        finding_id TEXT PRIMARY KEY REFERENCES findings(id), attacker_identity TEXT, preconditions TEXT,
        entry_point TEXT, attack_path TEXT, control_case TEXT, proof_case TEXT, observed_result TEXT,
        impact TEXT, confidence REAL, limitations TEXT, root_cause TEXT, remediation TEXT, fix_verification TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS developer_feedback (
        id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id), decision TEXT NOT NULL,
        reviewer TEXT, reason TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS hypotheses (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        fingerprint TEXT NOT NULL, title TEXT NOT NULL, attack_class TEXT NOT NULL, security_invariant TEXT NOT NULL,
        rank REAL NOT NULL, evidence_ids_json TEXT NOT NULL, rationale TEXT NOT NULL, state TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(project_id, snapshot_id, fingerprint)
      );
      CREATE TABLE IF NOT EXISTS validation_attempts (
        id TEXT PRIMARY KEY, hypothesis_id TEXT NOT NULL REFERENCES hypotheses(id), task_id TEXT REFERENCES tasks(id),
        mode TEXT NOT NULL, outcome TEXT NOT NULL, evidence_ids_json TEXT NOT NULL, details_json TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS remediation_tasks (
        id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id), task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id),
        state TEXT NOT NULL, plan_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cache_entries (
        cache_key TEXT PRIMARY KEY, value_json TEXT NOT NULL, source_revision TEXT NOT NULL,
        expires_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS threat_models (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        version INTEGER NOT NULL, status TEXT NOT NULL, document_json TEXT NOT NULL, artifact_id TEXT REFERENCES artifacts(id),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(project_id, snapshot_id, version)
      );
      CREATE TABLE IF NOT EXISTS scope_policies (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        version INTEGER NOT NULL, document_json TEXT NOT NULL, artifact_id TEXT REFERENCES artifacts(id),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(project_id, snapshot_id, version)
      );
      CREATE TABLE IF NOT EXISTS finding_events (
        id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id), from_state TEXT, to_state TEXT NOT NULL, reason TEXT, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS coverage (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), snapshot_id TEXT REFERENCES snapshots(id),
        area TEXT NOT NULL, attack_class TEXT NOT NULL, depth TEXT NOT NULL CHECK(depth IN ('none','partial','standard','deep')),
        reviewed_entities_json TEXT NOT NULL, evidence_ids_json TEXT NOT NULL, proof_gaps_json TEXT NOT NULL,
        source_revision TEXT NOT NULL, stale INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE(project_id, snapshot_id, area, attack_class)
      );
      CREATE TABLE IF NOT EXISTS agent_runs (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), task_id TEXT REFERENCES tasks(id),
        provider TEXT, model TEXT, task_type TEXT NOT NULL, prompt_version TEXT, schema_version TEXT,
        input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0,
        latency_ms INTEGER, cache_hit INTEGER NOT NULL DEFAULT 0, outcome TEXT, created_at TEXT NOT NULL
      );
    `);
    this.addColumnIfMissing("tasks", "attempts", "INTEGER NOT NULL DEFAULT 0");
    this.addColumnIfMissing("tasks", "worker_id", "TEXT");
    this.addColumnIfMissing("tasks", "lease_expires_at", "TEXT");
    this.addColumnIfMissing("tasks", "last_error", "TEXT");
  }

  addColumnIfMissing(table, column, definition) {
    const columns = this.db.prepare(`PRAGMA table_info(${table})`).all().map((entry) => entry.name);
    if (!columns.includes(column)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }

  createProject(name) {
    if (!name?.trim()) throw new Error("Project name is required");
    const project = { id: id(), name: name.trim(), created_at: now() };
    this.db.prepare("INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)").run(project.id, project.name, project.created_at);
    return project;
  }

  getProjectByName(name) { return this.db.prepare("SELECT * FROM projects WHERE name = ?").get(name) ?? null; }
  findOrCreateProject(name) { return this.getProjectByName(name) ?? this.createProject(name); }
  getProject(projectId) { return this.db.prepare("SELECT * FROM projects WHERE id = ?").get(projectId) ?? null; }
  listProjects() { return this.db.prepare("SELECT * FROM projects ORDER BY created_at DESC").all(); }

  createSnapshot(projectId, revision) {
    const existing = this.db.prepare("SELECT * FROM snapshots WHERE project_id = ? AND revision = ?").get(projectId, revision);
    if (existing) return existing;
    const snapshot = { id: id(), project_id: projectId, revision, created_at: now() };
    this.db.prepare("INSERT INTO snapshots (id, project_id, revision, created_at) VALUES (?, ?, ?, ?)").run(snapshot.id, snapshot.project_id, snapshot.revision, snapshot.created_at);
    return snapshot;
  }

  getSnapshotByRevision(projectId, revision) { return this.db.prepare("SELECT * FROM snapshots WHERE project_id = ? AND revision = ?").get(projectId, revision) ?? null; }

  getSnapshot(snapshotId) { return this.db.prepare("SELECT * FROM snapshots WHERE id = ?").get(snapshotId) ?? null; }

  latestSnapshot(projectId) { return this.db.prepare("SELECT * FROM snapshots WHERE project_id = ? ORDER BY created_at DESC LIMIT 1").get(projectId) ?? null; }

  createTask({ projectId, snapshotId = null, kind, scope = {}, priority = 0 }) {
    if (!kind?.trim()) throw new Error("Task kind is required");
    const timestamp = now();
    const task = { id: id(), project_id: projectId, snapshot_id: snapshotId, kind, state: "queued", scope_json: JSON.stringify(scope), priority: Number(priority) || 0, attempts: 0, worker_id: null, lease_expires_at: null, last_error: null, created_at: timestamp, updated_at: timestamp };
    this.db.prepare("INSERT INTO tasks (id, project_id, snapshot_id, kind, state, scope_json, priority, attempts, worker_id, lease_expires_at, last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(task.id, task.project_id, task.snapshot_id, task.kind, task.state, task.scope_json, task.priority, task.attempts, task.worker_id, task.lease_expires_at, task.last_error, task.created_at, task.updated_at);
    return task;
  }

  listTasks(projectId = null) {
    const sql = projectId ? "SELECT * FROM tasks WHERE project_id = ? ORDER BY priority DESC, created_at" : "SELECT * FROM tasks ORDER BY priority DESC, created_at";
    return (projectId ? this.db.prepare(sql).all(projectId) : this.db.prepare(sql).all()).map((task) => ({ ...task, scope: JSON.parse(task.scope_json) }));
  }

  getTask(taskId) {
    const task = this.db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
    return task ? { ...task, scope: JSON.parse(task.scope_json) } : null;
  }

  updateTaskState(taskId, state, { error = null } = {}) {
    if (!taskStates.has(state)) throw new Error(`Unknown task state: ${state}`);
    const result = this.db.prepare("UPDATE tasks SET state = ?, last_error = ?, worker_id = CASE WHEN ? IN ('completed','failed','blocked','queued') THEN NULL ELSE worker_id END, lease_expires_at = CASE WHEN ? IN ('completed','failed','blocked','queued') THEN NULL ELSE lease_expires_at END, updated_at = ? WHERE id = ?")
      .run(state, error, state, state, now(), taskId);
    if (result.changes !== 1) throw new Error(`Task not found: ${taskId}`);
  }

  claimNextTask({ workerId, leaseSeconds = 300, projectId = null, kinds = null }) {
    if (!workerId?.trim()) throw new Error("Worker id is required");
    const timestamp = now();
    const expires = new Date(Date.now() + Math.max(1, Number(leaseSeconds) || 300) * 1000).toISOString();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const kindClause = Array.isArray(kinds) && kinds.length ? ` AND kind IN (${kinds.map(() => "?").join(",")})` : "";
      const sql = projectId
        ? `SELECT * FROM tasks WHERE project_id = ? AND (state = 'queued' OR (state = 'running' AND lease_expires_at < ?))${kindClause} ORDER BY priority DESC, created_at LIMIT 1`
        : `SELECT * FROM tasks WHERE (state = 'queued' OR (state = 'running' AND lease_expires_at < ?))${kindClause} ORDER BY priority DESC, created_at LIMIT 1`;
      const parameters = projectId ? [projectId, timestamp, ...(kinds ?? [])] : [timestamp, ...(kinds ?? [])];
      const task = this.db.prepare(sql).get(...parameters);
      if (!task) { this.db.exec("COMMIT"); return null; }
      this.db.prepare("UPDATE tasks SET state = 'running', worker_id = ?, lease_expires_at = ?, attempts = attempts + 1, updated_at = ? WHERE id = ?")
        .run(workerId, expires, timestamp, task.id);
      this.db.exec("COMMIT");
      return { ...task, state: "running", worker_id: workerId, lease_expires_at: expires, attempts: task.attempts + 1, scope: JSON.parse(task.scope_json) };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  addArtifact({ projectId, snapshotId = null, kind, uri, contentHash = null, redacted = true }) {
    const artifact = { id: id(), project_id: projectId, snapshot_id: snapshotId, kind, uri, content_hash: contentHash, redacted: redacted ? 1 : 0, created_at: now() };
    this.db.prepare("INSERT INTO artifacts (id, project_id, snapshot_id, kind, uri, content_hash, redacted, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(artifact.id, artifact.project_id, artifact.snapshot_id, artifact.kind, artifact.uri, artifact.content_hash, artifact.redacted, artifact.created_at);
    return artifact;
  }

  latestArtifact({ projectId, snapshotId, kind }) { return this.db.prepare("SELECT * FROM artifacts WHERE project_id = ? AND snapshot_id = ? AND kind = ? ORDER BY created_at DESC LIMIT 1").get(projectId, snapshotId, kind) ?? null; }

  addSignal({ projectId, snapshotId = null, tool, ruleId, severity = null, message, location = {}, artifactId = null }) {
    const signal = { id: id(), project_id: projectId, snapshot_id: snapshotId, tool, rule_id: ruleId, severity, message, location_json: JSON.stringify(location), artifact_id: artifactId, created_at: now() };
    this.db.prepare("INSERT INTO signals (id, project_id, snapshot_id, tool, rule_id, severity, message, location_json, artifact_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(signal.id, signal.project_id, signal.snapshot_id, signal.tool, signal.rule_id, signal.severity, signal.message, signal.location_json, signal.artifact_id, signal.created_at);
    return signal;
  }

  listSignals(projectId) { return this.db.prepare("SELECT * FROM signals WHERE project_id = ? ORDER BY created_at DESC").all(projectId); }

  addEvidence({ projectId, snapshotId = null, kind, summary, artifactUri = null, sourceRevision, observed = {}, redacted = true }) {
    if (!kind?.trim() || !summary?.trim()) throw new Error("Evidence kind and summary are required");
    if (!sourceRevision?.trim()) throw new Error("Evidence requires source_revision");
    const evidence = { id: id(), project_id: projectId, snapshot_id: snapshotId, kind, summary, artifact_uri: artifactUri, source_revision: sourceRevision, observed_json: JSON.stringify(observed), redacted: redacted ? 1 : 0, created_at: now() };
    this.db.prepare("INSERT INTO evidence (id, project_id, snapshot_id, kind, summary, artifact_uri, source_revision, observed_json, redacted, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(evidence.id, evidence.project_id, evidence.snapshot_id, evidence.kind, evidence.summary, evidence.artifact_uri, evidence.source_revision, evidence.observed_json, evidence.redacted, evidence.created_at);
    return { ...evidence, observed };
  }

  getEvidence(evidenceId) {
    const evidence = this.db.prepare("SELECT * FROM evidence WHERE id = ?").get(evidenceId);
    return evidence ? { ...evidence, observed: JSON.parse(evidence.observed_json) } : null;
  }

  listEvidenceForIds(evidenceIds = []) {
    if (!evidenceIds.length) return [];
    return evidenceIds.map((evidenceId) => this.getEvidence(evidenceId)).filter(Boolean);
  }

  createConfirmedFindingFromHypothesis({ hypothesisId, title = null, details = {}, evidenceIds = [] }) {
    const hypothesis = this.getHypothesis(hypothesisId);
    if (!hypothesis) throw new Error(`Hypothesis not found: ${hypothesisId}`);
    const ids = [...new Set(evidenceIds.length ? evidenceIds : JSON.parse(hypothesis.evidence_ids_json))];
    if (!ids.length) throw new Error("A confirmed finding requires explicit evidence IDs");
    const evidence = this.listEvidenceForIds(ids);
    if (evidence.length !== ids.length) throw new Error("Every evidence ID must exist before promotion");
    if (evidence.some((item) => item.project_id !== hypothesis.project_id)) throw new Error("Evidence must belong to the same project as the hypothesis");
    const required = ["attacker_identity", "preconditions", "entry_point", "attack_path", "control_case", "proof_case", "observed_result", "impact", "root_cause", "remediation", "fix_verification"];
    for (const field of required) if (!String(details[field] ?? "").trim()) throw new Error(`Confirmed finding requires ${field}`);
    if (!Number.isFinite(Number(details.confidence))) throw new Error("Confirmed finding requires numeric confidence");
    const timestamp = now();
    const finding = { id: id(), project_id: hypothesis.project_id, snapshot_id: hypothesis.snapshot_id, title: title || hypothesis.title, state: "CONFIRMED", security_invariant: hypothesis.security_invariant, evidence_ids_json: JSON.stringify(ids), created_at: timestamp, updated_at: timestamp };
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO findings (id, project_id, snapshot_id, title, state, security_invariant, evidence_ids_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(finding.id, finding.project_id, finding.snapshot_id, finding.title, finding.state, finding.security_invariant, finding.evidence_ids_json, finding.created_at, finding.updated_at);
      const path = ["SIGNAL", "HYPOTHESIS", "UNDER_REVIEW", "VALIDATION_PLANNED", "CONFIRMED"];
      for (let index = 0; index < path.length; index += 1) this.db.prepare("INSERT INTO finding_events (id, finding_id, from_state, to_state, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(id(), finding.id, index ? path[index - 1] : null, path[index], index === path.length - 1 ? "promoted from hypothesis with explicit evidence" : "promotion trace", timestamp);
      this.db.prepare("INSERT INTO finding_details (finding_id, attacker_identity, preconditions, entry_point, attack_path, control_case, proof_case, observed_result, impact, confidence, limitations, root_cause, remediation, fix_verification, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(finding.id, details.attacker_identity, details.preconditions, details.entry_point, details.attack_path, details.control_case, details.proof_case, details.observed_result, details.impact, Number(details.confidence), details.limitations ?? null, details.root_cause, details.remediation, details.fix_verification, timestamp, timestamp);
      this.db.prepare("UPDATE hypotheses SET state = 'CONFIRMED', updated_at = ? WHERE id = ?").run(timestamp, hypothesisId);
      this.db.exec("COMMIT");
      return { ...finding, details, evidence };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  addContextNode({ projectId, snapshotId = null, kind, label, attributes = {}, provenance }) {
    const existing = this.db.prepare("SELECT * FROM nodes WHERE project_id = ? AND snapshot_id IS ? AND kind = ? AND label = ?").get(projectId, snapshotId, kind, label);
    if (existing) return existing;
    const node = { id: id(), project_id: projectId, snapshot_id: snapshotId, kind, label, attributes_json: JSON.stringify(attributes), provenance_json: JSON.stringify(provenance), created_at: now() };
    this.db.prepare("INSERT INTO nodes (id, project_id, snapshot_id, kind, label, attributes_json, provenance_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(node.id, node.project_id, node.snapshot_id, node.kind, node.label, node.attributes_json, node.provenance_json, node.created_at);
    return node;
  }

  addContextEdge({ projectId, snapshotId = null, fromNodeId, toNodeId, kind, attributes = {}, provenance }) {
    const existing = this.db.prepare("SELECT * FROM edges WHERE project_id = ? AND snapshot_id IS ? AND from_node_id = ? AND to_node_id = ? AND kind = ?").get(projectId, snapshotId, fromNodeId, toNodeId, kind);
    if (existing) return existing;
    const edge = { id: id(), project_id: projectId, snapshot_id: snapshotId, from_node_id: fromNodeId, to_node_id: toNodeId, kind, attributes_json: JSON.stringify(attributes), provenance_json: JSON.stringify(provenance), created_at: now() };
    this.db.prepare("INSERT INTO edges (id, project_id, snapshot_id, from_node_id, to_node_id, kind, attributes_json, provenance_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(edge.id, edge.project_id, edge.snapshot_id, edge.from_node_id, edge.to_node_id, edge.kind, edge.attributes_json, edge.provenance_json, edge.created_at);
    return edge;
  }

  searchContextNodes({ projectId, snapshotId = null, query, limit = 20 }) {
    return this.db.prepare("SELECT * FROM nodes WHERE project_id = ? AND snapshot_id IS ? AND label LIKE ? ORDER BY CASE WHEN label = ? THEN 0 ELSE 1 END, label LIMIT ?")
      .all(projectId, snapshotId, `%${query}%`, query, Math.max(1, Number(limit) || 20));
  }

  contextNeighborhood({ projectId, snapshotId = null, nodeId }) {
    const center = this.db.prepare("SELECT * FROM nodes WHERE project_id = ? AND snapshot_id IS ? AND id = ?").get(projectId, snapshotId, nodeId);
    if (!center) return null;
    const edges = this.db.prepare("SELECT * FROM edges WHERE project_id = ? AND snapshot_id IS ? AND (from_node_id = ? OR to_node_id = ?)").all(projectId, snapshotId, nodeId, nodeId);
    const ids = [...new Set(edges.flatMap((edge) => [edge.from_node_id, edge.to_node_id]))];
    const nodes = ids.length ? this.db.prepare(`SELECT * FROM nodes WHERE id IN (${ids.map(() => "?").join(",")})`).all(...ids) : [center];
    return { center, nodes, edges };
  }

  addClaim({ projectId, snapshotId = null, kind, summary, provenance }) {
    if (!["observation", "fact", "assumption", "invariant", "hypothesis"].includes(kind)) throw new Error(`Unsupported claim kind: ${kind}`);
    if (!provenance?.origin || !provenance?.source_revision) throw new Error("Claims require provenance origin and source_revision");
    const claim = { id: id(), project_id: projectId, snapshot_id: snapshotId, kind, summary, provenance_json: JSON.stringify(provenance), created_at: now() };
    this.db.prepare("INSERT INTO claims (id, project_id, snapshot_id, kind, summary, provenance_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(claim.id, claim.project_id, claim.snapshot_id, claim.kind, claim.summary, claim.provenance_json, claim.created_at);
    return claim;
  }

  createHypothesis({ projectId, snapshotId = null, fingerprint, title, attackClass, securityInvariant, rank, evidenceIds = [], rationale }) {
    const existing = this.db.prepare("SELECT * FROM hypotheses WHERE project_id = ? AND snapshot_id IS ? AND fingerprint = ?").get(projectId, snapshotId, fingerprint);
    if (existing) return existing;
    const hypothesis = { id: id(), project_id: projectId, snapshot_id: snapshotId, fingerprint, title, attack_class: attackClass, security_invariant: securityInvariant, rank, evidence_ids_json: JSON.stringify(evidenceIds), rationale, state: "HYPOTHESIS", created_at: now(), updated_at: now() };
    this.db.prepare("INSERT INTO hypotheses (id, project_id, snapshot_id, fingerprint, title, attack_class, security_invariant, rank, evidence_ids_json, rationale, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(hypothesis.id, hypothesis.project_id, hypothesis.snapshot_id, hypothesis.fingerprint, hypothesis.title, hypothesis.attack_class, hypothesis.security_invariant, hypothesis.rank, hypothesis.evidence_ids_json, hypothesis.rationale, hypothesis.state, hypothesis.created_at, hypothesis.updated_at);
    return hypothesis;
  }

  getHypothesis(hypothesisId) { return this.db.prepare("SELECT * FROM hypotheses WHERE id = ?").get(hypothesisId) ?? null; }
  listHypotheses(projectId) { return this.db.prepare("SELECT * FROM hypotheses WHERE project_id = ? ORDER BY rank DESC, created_at").all(projectId); }
  updateHypothesisState(hypothesisId, state) {
    const allowed = new Set(["HYPOTHESIS", "VALIDATION_PLANNED", "VALIDATION_BLOCKED", "REJECTED", "PARTIALLY_VALIDATED", "CONFIRMED"]);
    if (!allowed.has(state)) throw new Error(`Unknown hypothesis state: ${state}`);
    const result = this.db.prepare("UPDATE hypotheses SET state = ?, updated_at = ? WHERE id = ?").run(state, now(), hypothesisId);
    if (result.changes !== 1) throw new Error(`Hypothesis not found: ${hypothesisId}`);
  }
  recordValidationAttempt({ hypothesisId, taskId = null, mode, outcome, evidenceIds = [], details = {} }) {
    const attempt = { id: id(), hypothesis_id: hypothesisId, task_id: taskId, mode, outcome, evidence_ids_json: JSON.stringify(evidenceIds), details_json: JSON.stringify(details), created_at: now() };
    this.db.prepare("INSERT INTO validation_attempts (id, hypothesis_id, task_id, mode, outcome, evidence_ids_json, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(attempt.id, attempt.hypothesis_id, attempt.task_id, attempt.mode, attempt.outcome, attempt.evidence_ids_json, attempt.details_json, attempt.created_at);
    return attempt;
  }

  upsertCoverage({ projectId, snapshotId = null, area, attackClass, depth = "none", reviewedEntities = [], evidenceIds = [], proofGaps = [], sourceRevision, stale = false }) {
    const timestamp = now();
    const existing = this.db.prepare("SELECT id, created_at FROM coverage WHERE project_id = ? AND snapshot_id IS ? AND area = ? AND attack_class = ?").get(projectId, snapshotId, area, attackClass);
    const record = { id: existing?.id ?? id(), project_id: projectId, snapshot_id: snapshotId, area, attack_class: attackClass, depth, reviewed_entities_json: JSON.stringify(reviewedEntities), evidence_ids_json: JSON.stringify(evidenceIds), proof_gaps_json: JSON.stringify(proofGaps), source_revision: sourceRevision, stale: stale ? 1 : 0, created_at: existing?.created_at ?? timestamp, updated_at: timestamp };
    this.db.prepare("INSERT INTO coverage (id, project_id, snapshot_id, area, attack_class, depth, reviewed_entities_json, evidence_ids_json, proof_gaps_json, source_revision, stale, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, snapshot_id, area, attack_class) DO UPDATE SET depth=excluded.depth, reviewed_entities_json=excluded.reviewed_entities_json, evidence_ids_json=excluded.evidence_ids_json, proof_gaps_json=excluded.proof_gaps_json, source_revision=excluded.source_revision, stale=excluded.stale, updated_at=excluded.updated_at")
      .run(record.id, record.project_id, record.snapshot_id, record.area, record.attack_class, record.depth, record.reviewed_entities_json, record.evidence_ids_json, record.proof_gaps_json, record.source_revision, record.stale, record.created_at, record.updated_at);
    return record;
  }

  listCoverage(projectId) { return this.db.prepare("SELECT * FROM coverage WHERE project_id = ? ORDER BY area, attack_class").all(projectId); }
  markCoverageStale(snapshotId) { return this.db.prepare("UPDATE coverage SET stale = 1, updated_at = ? WHERE snapshot_id = ?").run(now(), snapshotId).changes; }

  recordAgentRun({ projectId, taskId = null, provider = null, model = null, taskType, promptVersion = null, schemaVersion = null, inputTokens = 0, outputTokens = 0, cost = 0, latencyMs = null, cacheHit = false, outcome = null }) {
    const run = { id: id(), project_id: projectId, task_id: taskId, provider, model, task_type: taskType, prompt_version: promptVersion, schema_version: schemaVersion, input_tokens: inputTokens, output_tokens: outputTokens, cost, latency_ms: latencyMs, cache_hit: cacheHit ? 1 : 0, outcome, created_at: now() };
    this.db.prepare("INSERT INTO agent_runs (id, project_id, task_id, provider, model, task_type, prompt_version, schema_version, input_tokens, output_tokens, cost, latency_ms, cache_hit, outcome, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(run.id, run.project_id, run.task_id, run.provider, run.model, run.task_type, run.prompt_version, run.schema_version, run.input_tokens, run.output_tokens, run.cost, run.latency_ms, run.cache_hit, run.outcome, run.created_at);
    return run;
  }

  getCache(cacheKey) {
    const entry = this.db.prepare("SELECT * FROM cache_entries WHERE cache_key = ?").get(cacheKey);
    if (!entry) return null;
    if (entry.expires_at && entry.expires_at < now()) { this.db.prepare("DELETE FROM cache_entries WHERE cache_key = ?").run(cacheKey); return null; }
    return { ...entry, value: JSON.parse(entry.value_json) };
  }

  setCache({ cacheKey, value, sourceRevision, expiresAt = null }) {
    const timestamp = now();
    this.db.prepare("INSERT INTO cache_entries (cache_key, value_json, source_revision, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(cache_key) DO UPDATE SET value_json=excluded.value_json, source_revision=excluded.source_revision, expires_at=excluded.expires_at, updated_at=excluded.updated_at")
      .run(cacheKey, JSON.stringify(value), sourceRevision, expiresAt, timestamp, timestamp);
  }

  getLatestThreatModel(projectId, snapshotId) {
    const model = this.db.prepare("SELECT * FROM threat_models WHERE project_id = ? AND snapshot_id IS ? ORDER BY version DESC LIMIT 1").get(projectId, snapshotId);
    return model ? { ...model, document: JSON.parse(model.document_json) } : null;
  }

  saveThreatModel({ projectId, snapshotId = null, document, status = "draft", artifactId = null }) {
    if (!document?.system_purpose || !Array.isArray(document.assets) || !Array.isArray(document.entry_points) || !Array.isArray(document.trust_boundaries) || !Array.isArray(document.invariants)) {
      throw new Error("Threat model requires system_purpose, assets, entry_points, trust_boundaries, and invariants.");
    }
    const previous = this.getLatestThreatModel(projectId, snapshotId);
    const timestamp = now();
    const record = { id: id(), project_id: projectId, snapshot_id: snapshotId, version: (previous?.version ?? 0) + 1, status, document_json: JSON.stringify(document), artifact_id: artifactId, created_at: timestamp, updated_at: timestamp };
    this.db.prepare("INSERT INTO threat_models (id, project_id, snapshot_id, version, status, document_json, artifact_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(record.id, record.project_id, record.snapshot_id, record.version, record.status, record.document_json, record.artifact_id, record.created_at, record.updated_at);
    return { ...record, document };
  }

  getLatestScopePolicy(projectId, snapshotId) {
    const policy = this.db.prepare("SELECT * FROM scope_policies WHERE project_id = ? AND snapshot_id IS ? ORDER BY version DESC LIMIT 1").get(projectId, snapshotId);
    return policy ? { ...policy, document: JSON.parse(policy.document_json) } : null;
  }

  saveScopePolicy({ projectId, snapshotId = null, document, artifactId = null }) {
    if (!document?.target_mode || !Array.isArray(document.primary_targets) || typeof document.active_testing !== "boolean") throw new Error("Scope policy requires target_mode, primary_targets, and active_testing.");
    const previous = this.getLatestScopePolicy(projectId, snapshotId);
    const timestamp = now();
    const record = { id: id(), project_id: projectId, snapshot_id: snapshotId, version: (previous?.version ?? 0) + 1, document_json: JSON.stringify(document), artifact_id: artifactId, created_at: timestamp, updated_at: timestamp };
    this.db.prepare("INSERT INTO scope_policies (id, project_id, snapshot_id, version, document_json, artifact_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(record.id, record.project_id, record.snapshot_id, record.version, record.document_json, record.artifact_id, record.created_at, record.updated_at);
    return { ...record, document };
  }

  createFinding({ projectId, snapshotId = null, title, securityInvariant, evidenceIds = [] }) {
    if (!securityInvariant?.trim()) throw new Error("A finding requires a security invariant");
    const finding = { id: id(), project_id: projectId, snapshot_id: snapshotId, title, state: "SIGNAL", security_invariant: securityInvariant, evidence_ids_json: JSON.stringify(evidenceIds), created_at: now(), updated_at: now() };
    this.db.prepare("INSERT INTO findings (id, project_id, snapshot_id, title, state, security_invariant, evidence_ids_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(finding.id, finding.project_id, finding.snapshot_id, finding.title, finding.state, finding.security_invariant, finding.evidence_ids_json, finding.created_at, finding.updated_at);
    this.db.prepare("INSERT INTO finding_events (id, finding_id, from_state, to_state, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(id(), finding.id, null, "SIGNAL", "created", finding.created_at);
    return finding;
  }

  getFinding(findingId) { return this.db.prepare("SELECT * FROM findings WHERE id = ?").get(findingId) ?? null; }

  getFindingDetails(findingId) {
    const details = this.db.prepare("SELECT * FROM finding_details WHERE finding_id = ?").get(findingId);
    return details ?? null;
  }

  recordDeveloperFeedback({ findingId, decision, reviewer = null, reason }) {
    const allowed = new Set(["accepted", "dismissed", "fixed", "risk-accepted"]);
    if (!allowed.has(decision)) throw new Error(`Unsupported feedback decision: ${decision}`);
    if (!reason?.trim()) throw new Error("Developer feedback requires a reason");
    const finding = this.db.prepare("SELECT * FROM findings WHERE id = ?").get(findingId);
    if (!finding) throw new Error(`Finding not found: ${findingId}`);
    const feedback = { id: id(), finding_id: findingId, decision, reviewer, reason, created_at: now() };
    this.db.prepare("INSERT INTO developer_feedback (id, finding_id, decision, reviewer, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(feedback.id, feedback.finding_id, feedback.decision, feedback.reviewer, feedback.reason, feedback.created_at);
    const transitions = { accepted: "ACCEPTED", dismissed: "REJECTED", "risk-accepted": "RISK_ACCEPTED" };
    if (transitions[decision] && finding.state !== transitions[decision]) this.transitionFinding(findingId, transitions[decision], `developer feedback: ${decision}`);
    return feedback;
  }

  listFeedback(findingId) { return this.db.prepare("SELECT * FROM developer_feedback WHERE finding_id = ? ORDER BY created_at DESC").all(findingId); }

  listFindings(projectId) { return this.db.prepare("SELECT * FROM findings WHERE project_id = ? ORDER BY updated_at DESC").all(projectId); }
  listAgentRuns(projectId) { return this.db.prepare("SELECT * FROM agent_runs WHERE project_id = ? ORDER BY created_at DESC").all(projectId); }

  createRemediationTask(findingId) {
    const finding = this.db.prepare("SELECT * FROM findings WHERE id = ?").get(findingId);
    if (!finding) throw new Error(`Finding not found: ${findingId}`);
    if (finding.state !== "ACCEPTED") throw new Error("Only an ACCEPTED finding can receive a remediation task.");
    const existing = this.db.prepare("SELECT * FROM remediation_tasks WHERE finding_id = ?").get(findingId);
    if (existing) return existing;
    const plan = {
      finding_id: findingId,
      steps: ["Reproduce the original proof case.", "Identify root cause.", "Create a minimal patch.", "Add a regression test.", "Re-run the original proof and legitimate control case.", "Check nearby bypasses.", "Run relevant repository tests.", "Human review before closure."],
      fix_verification: "Transition PATCH_PROPOSED → FIX_VERIFIED only after the original proof no longer succeeds and legitimate behavior remains intact."
    };
    const task = this.createTask({ projectId: finding.project_id, snapshotId: finding.snapshot_id, kind: "remediation", priority: 1, scope: plan });
    const record = { id: id(), finding_id: findingId, task_id: task.id, state: "planned", plan_json: JSON.stringify(plan), created_at: now(), updated_at: now() };
    this.db.prepare("INSERT INTO remediation_tasks (id, finding_id, task_id, state, plan_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(record.id, record.finding_id, record.task_id, record.state, record.plan_json, record.created_at, record.updated_at);
    return { ...record, task };
  }

  transitionFinding(findingId, toState, reason = null) {
    if (!findingStates.has(toState)) throw new Error(`Unknown finding state: ${toState}`);
    const finding = this.db.prepare("SELECT * FROM findings WHERE id = ?").get(findingId);
    if (!finding) throw new Error(`Finding not found: ${findingId}`);
    if (!canTransition(finding.state, toState)) throw new Error(`Invalid finding transition: ${finding.state} → ${toState}`);
    const timestamp = now();
    this.db.prepare("UPDATE findings SET state = ?, updated_at = ? WHERE id = ?").run(toState, timestamp, findingId);
    this.db.prepare("INSERT INTO finding_events (id, finding_id, from_state, to_state, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(id(), findingId, finding.state, toState, reason, timestamp);
    return { ...finding, state: toState, updated_at: timestamp };
  }

  close() { this.db.close(); }
}
