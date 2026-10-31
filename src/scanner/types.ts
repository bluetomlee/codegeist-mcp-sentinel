/**
 * Core types for the MCP Sentinel scanner.
 *
 * The scanner is a pure, synchronous module: no I/O, no network, no Forge APIs.
 * Everything Forge-specific lives outside src/scanner/.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** A single MCP tool as returned by `tools/list` (subset of the MCP spec we care about). */
export interface McpTool {
  name: string;
  description?: string;
  title?: string;
  /** JSON Schema for the tool input. MCP calls this `inputSchema`. */
  inputSchema?: JsonSchema;
  annotations?: Record<string, unknown>;
}

export interface JsonSchema {
  type?: string | string[];
  description?: string;
  title?: string;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema | JsonSchema[];
  required?: string[];
  enum?: unknown[];
  default?: unknown;
  additionalProperties?: boolean | JsonSchema;
  [k: string]: unknown;
}

export interface McpServerDefinition {
  /** Stable identifier chosen by the user (e.g. "github-mcp"). */
  serverId: string;
  /** Human-readable name. */
  name?: string;
  tools: McpTool[];
}

export type RuleId =
  | 'hidden-instruction'
  | 'concealment'
  | 'exfil-url'
  | 'sensitive-file'
  | 'cross-tool-shadowing'
  | 'tool-name-collision'
  | 'invisible-unicode'
  | 'bidi-override'
  | 'homoglyph-name'
  | 'encoded-payload'
  | 'whitespace-padding'
  | 'fake-turn-boundary'
  | 'persistence'
  | 'excessive-permission'
  | 'parameter-smuggling'
  | 'rug-pull';

export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  /** Tool the finding applies to (empty string for server-level findings). */
  tool: string;
  /** Where in the tool definition the text was found, e.g. "description" or "inputSchema.properties.notes.description". */
  location: string;
  message: string;
  /** Short, sanitised excerpt (invisible characters made visible, truncated). */
  evidence: string;
}

export interface ToolFingerprint {
  name: string;
  /** SHA-256 over the canonicalised tool definition (name + description + inputSchema). */
  hash: string;
}

export interface ScanResult {
  serverId: string;
  serverName: string;
  scannedAt: string;
  toolCount: number;
  findings: Finding[];
  /** Highest severity across findings, or 'info' when clean. */
  maxSeverity: Severity;
  /** 0 (clean) .. 100 (very risky). */
  riskScore: number;
  fingerprints: ToolFingerprint[];
}

/** Previous snapshot used for rug-pull detection. */
export interface PreviousSnapshot {
  scannedAt: string;
  fingerprints: ToolFingerprint[];
}

export interface ScanOptions {
  /** Snapshot from an earlier scan of the same server, for rug-pull detection. */
  previous?: PreviousSnapshot;
  /**
   * Tool names known from other servers (or the host's builtins). Used for
   * cross-server shadowing and name-collision detection.
   */
  knownToolNames?: Array<{ server: string; name: string }>;
  /** Clock override for deterministic tests. */
  now?: () => Date;
}
