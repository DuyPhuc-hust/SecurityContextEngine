export interface ModelRequest { taskType: string; schemaVersion?: string; context: unknown; }

export interface ModelProvider {
  generateStructured<T>(request: ModelRequest): Promise<T>;
  generateReasoned(request: ModelRequest): Promise<string>;
  contextLimit(): number;
  supportsTools(): boolean;
  supportsLocal(): boolean;
  estimatedCost(request: ModelRequest): number;
}
