export type ClaimKind = "observation" | "fact" | "assumption" | "invariant" | "hypothesis" | "finding";

export type FindingState = "SIGNAL" | "HYPOTHESIS" | "UNDER_REVIEW" | "VALIDATION_PLANNED" | "VALIDATION_BLOCKED" | "REJECTED" | "PARTIALLY_VALIDATED" | "CONFIRMED" | "ACCEPTED" | "RISK_ACCEPTED" | "PATCH_PROPOSED" | "FIX_VERIFIED" | "CLOSED" | "REOPENED";

export interface Provenance {
  origin: "human" | "deterministic-tool" | "model" | "runtime";
  artifactIds: string[];
  sourceRevision: string;
  extractorVersion: string;
  confidence: number;
  createdAt: string;
  stale: boolean;
}

export interface Claim { id: string; kind: ClaimKind; projectId: string; summary: string; provenance: Provenance; }
export interface ContextNode { id: string; kind: string; label: string; revision: string; }
export interface ContextEdge { id: string; from: string; to: string; kind: string; provenance: Provenance; }
