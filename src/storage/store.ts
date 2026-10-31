import type { Finding, PreviousSnapshot, ScanResult, Severity } from '../scanner/types';

/** Max findings persisted per server (Forge KVS values are limited to ~240 KiB). */
export const MAX_STORED_FINDINGS = 200;

export interface ServerRecord {
  serverId: string;
  serverName: string;
  /** Most recent scan (findings may be truncated to MAX_STORED_FINDINGS). */
  lastScan: ScanResult;
  /**
   * Approved fingerprint baseline used for rug-pull detection. Set automatically on
   * the first scan; afterwards only changes when a user explicitly approves.
   */
  baseline: PreviousSnapshot;
  baselineApprovedBy?: string;
  /** Finding keys already filed in Jira → issue key, to avoid duplicates. */
  filedIssues: Record<string, string>;
  scanCount: number;
}

export interface ServerSummary {
  serverId: string;
  serverName: string;
  toolCount: number;
  riskScore: number;
  maxSeverity: Severity;
  findingCount: number;
  rugPull: boolean;
  scannedAt: string;
  scanCount: number;
  jiraIssues: string[];
}

export interface ScanStore {
  get(serverId: string): Promise<ServerRecord | undefined>;
  put(record: ServerRecord): Promise<void>;
  list(): Promise<ServerRecord[]>;
  delete(serverId: string): Promise<void>;
}

export function findingKey(f: Finding): string {
  return `${f.ruleId}|${f.tool}|${f.location}`;
}

export function toSummary(r: ServerRecord): ServerSummary {
  return {
    serverId: r.serverId,
    serverName: r.serverName,
    toolCount: r.lastScan.toolCount,
    riskScore: r.lastScan.riskScore,
    maxSeverity: r.lastScan.maxSeverity,
    findingCount: r.lastScan.findings.filter((f) => f.severity !== 'info').length,
    rugPull: r.lastScan.findings.some((f) => f.ruleId === 'rug-pull' && f.severity === 'high'),
    scannedAt: r.lastScan.scannedAt,
    scanCount: r.scanCount,
    jiraIssues: [...new Set(Object.values(r.filedIssues))],
  };
}

/** In-memory store for tests and local experimentation. */
export class MemoryScanStore implements ScanStore {
  private readonly data = new Map<string, ServerRecord>();
  async get(id: string) {
    const v = this.data.get(id);
    return v ? structuredClone(v) : undefined;
  }
  async put(r: ServerRecord) {
    this.data.set(r.serverId, structuredClone(r));
  }
  async list() {
    return [...this.data.values()].map((v) => structuredClone(v));
  }
  async delete(id: string) {
    this.data.delete(id);
  }
}
