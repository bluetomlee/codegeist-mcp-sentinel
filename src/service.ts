/**
 * Application service: orchestrates scanner + storage + Jira.
 * Dependencies are injected so the whole flow is unit-testable without Forge.
 */
import { atLeast, formatFindingsMarkdown, parseToolList, scanServer, scoreFindings, summarizeResult } from './scanner';
import type { Finding, ScanResult, Severity } from './scanner/types';
import { SEVERITY_ORDER } from './scanner/types';
import { MAX_STORED_FINDINGS, findingKey, toSummary, type ScanStore, type ServerRecord, type ServerSummary } from './storage/store';
import { findingToAdf, issueSummary } from './jira/adf';
import { isValidProjectKey, type JiraClient } from './jira/client';

export interface Deps {
  store: ScanStore;
  jira: JiraClient;
  now?: () => Date;
}

const SERVER_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export class UserInputError extends Error {}

export function normalizeServerId(raw: unknown): string {
  const id = String(raw ?? '').trim();
  if (!SERVER_ID_RE.test(id)) {
    throw new UserInputError('serverId must be 1-64 chars: letters, digits, ".", "_" or "-" (e.g. "github-mcp").');
  }
  return id;
}

export function parseSeverity(raw: unknown, fallback: Severity): Severity {
  const s = String(raw ?? '').trim().toLowerCase();
  return (SEVERITIES as string[]).includes(s) ? (s as Severity) : fallback;
}

export interface ScanRequest {
  serverId: string;
  serverName?: string;
  toolsJson: string;
}

export interface ScanResponse {
  summary: string;
  report: string;
  result: ScanResult;
  baselineCreated: boolean;
}

export async function scanAndStore(deps: Deps, req: ScanRequest): Promise<ScanResponse> {
  const serverId = normalizeServerId(req.serverId);
  const tools = parseToolList(req.toolsJson);
  const existing = await deps.store.get(serverId);
  const others = (await deps.store.list()).filter((r) => r.serverId !== serverId);

  const result = scanServer(
    { serverId, name: req.serverName?.trim() || existing?.serverName || serverId, tools },
    {
      now: deps.now,
      previous: existing?.baseline,
      knownToolNames: others.flatMap((r) => r.lastScan.fingerprints.map((fp) => ({ server: r.serverId, name: fp.name }))),
    },
  );

  const stored: ScanResult = { ...result, findings: result.findings.slice(0, MAX_STORED_FINDINGS) };
  const record: ServerRecord = {
    serverId,
    serverName: result.serverName,
    lastScan: stored,
    baseline: existing?.baseline ?? { scannedAt: result.scannedAt, fingerprints: result.fingerprints },
    baselineApprovedBy: existing?.baselineApprovedBy,
    filedIssues: existing?.filedIssues ?? {},
    scanCount: (existing?.scanCount ?? 0) + 1,
  };
  await deps.store.put(record);

  return { summary: summarizeResult(result), report: formatFindingsMarkdown(result), result, baselineCreated: !existing };
}

export async function listServers(deps: Deps): Promise<ServerSummary[]> {
  const all = await deps.store.list();
  return all
    .map(toSummary)
    .sort((a, b) => SEVERITY_ORDER[b.maxSeverity] - SEVERITY_ORDER[a.maxSeverity] || b.riskScore - a.riskScore);
}

export async function getServer(deps: Deps, serverIdRaw: unknown): Promise<ServerRecord> {
  const serverId = normalizeServerId(serverIdRaw);
  const rec = await deps.store.get(serverId);
  if (!rec) throw new UserInputError(`No scan found for server "${serverId}". Scan it first.`);
  return rec;
}

/** Accept the current tool definitions as the trusted baseline (clears rug-pull alerts on next scan). */
export async function approveBaseline(deps: Deps, serverIdRaw: unknown, accountId?: string): Promise<ServerRecord> {
  const rec = await getServer(deps, serverIdRaw);
  rec.baseline = { scannedAt: rec.lastScan.scannedAt, fingerprints: rec.lastScan.fingerprints };
  rec.baselineApprovedBy = accountId;
  const findings = rec.lastScan.findings.filter((f) => f.ruleId !== 'rug-pull');
  rec.lastScan = { ...rec.lastScan, findings, ...scoreFindings(findings) };
  await deps.store.put(rec);
  return rec;
}

export async function deleteServer(deps: Deps, serverIdRaw: unknown): Promise<void> {
  await deps.store.delete(normalizeServerId(serverIdRaw));
}

export interface FileIssuesResult {
  created: Array<{ key: string; finding: Finding }>;
  skippedAlreadyFiled: number;
  errors: string[];
}

export const MAX_ISSUES_PER_CALL = 10;

/** File one Jira issue per finding at or above `minSeverity`, skipping ones already filed. */
export async function fileJiraIssues(
  deps: Deps,
  args: { serverId: unknown; projectKey: unknown; minSeverity?: unknown },
): Promise<FileIssuesResult> {
  const rec = await getServer(deps, args.serverId);
  const projectKey = String(args.projectKey ?? '').trim().toUpperCase();
  if (!isValidProjectKey(projectKey)) throw new UserInputError(`"${projectKey}" is not a valid Jira project key.`);
  const min = parseSeverity(args.minSeverity, 'high');

  const out: FileIssuesResult = { created: [], skippedAlreadyFiled: 0, errors: [] };
  for (const f of atLeast(rec.lastScan.findings, min)) {
    const k = findingKey(f);
    if (rec.filedIssues[k]) {
      out.skippedAlreadyFiled++;
      continue;
    }
    if (out.created.length >= MAX_ISSUES_PER_CALL) break;
    try {
      const key = await deps.jira.createIssue({
        projectKey,
        summary: issueSummary(f, rec.lastScan),
        description: findingToAdf(f, rec.lastScan),
        labels: ['mcp-sentinel', `mcp-${f.severity}`, `mcp-rule-${f.ruleId}`],
      });
      rec.filedIssues[k] = key;
      out.created.push({ key, finding: f });
    } catch (e) {
      out.errors.push((e as Error).message);
      break; // most failures (permissions, bad project) will repeat — stop early
    }
  }
  await deps.store.put(rec);
  return out;
}
