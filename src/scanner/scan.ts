import { createHash } from 'node:crypto';
import type {
  Finding,
  McpServerDefinition,
  McpTool,
  PreviousSnapshot,
  ScanOptions,
  ScanResult,
  Severity,
  ToolFingerprint,
} from './types';
import { SEVERITY_ORDER } from './types';
import { canonicalJson, extractTextFields } from './text';
import { normalizeForAnalysis } from './unicode';
import {
  type RuleContext,
  ruleConcealment,
  ruleCrossToolShadowing,
  ruleEncodedPayload,
  ruleExcessivePermission,
  ruleExfilUrl,
  ruleFakeTurnBoundary,
  ruleHiddenInstruction,
  ruleInvisibleUnicode,
  ruleParameterSmuggling,
  rulePersistence,
  ruleSensitiveFile,
  ruleToolNameChecks,
  ruleWhitespacePadding,
} from './rules';

const SEVERITY_WEIGHT: Record<Severity, number> = { info: 0, low: 3, medium: 10, high: 25, critical: 45 };

/** SHA-256 of the canonical, model-visible tool definition. */
export function fingerprintTool(tool: McpTool): ToolFingerprint {
  const canonical = canonicalJson({
    name: tool.name,
    title: tool.title,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? {},
  });
  return { name: tool.name, hash: createHash('sha256').update(canonical, 'utf8').digest('hex') };
}

/** Scan a single tool. Exported for unit tests and for the per-tool Rovo action. */
export function scanTool(tool: McpTool, ctx: Omit<RuleContext, 'tool'> = { siblingNames: [], externalNames: [] }): Finding[] {
  const fullCtx: RuleContext = { ...ctx, tool };
  const findings: Finding[] = [];
  const fields = extractTextFields(tool);
  const normalizedParts: string[] = [];

  for (const field of fields) {
    const text = normalizeForAnalysis(field.raw);
    normalizedParts.push(text);
    findings.push(
      ...ruleInvisibleUnicode(field, field.raw, fullCtx),
      ...ruleWhitespacePadding(field, field.raw, fullCtx),
    );
    if (field.location.endsWith('#name')) continue; // property names: unicode checks only
    findings.push(
      ...ruleHiddenInstruction(field, text, fullCtx),
      ...ruleConcealment(field, text, fullCtx),
      ...ruleExfilUrl(field, text, fullCtx),
      ...ruleSensitiveFile(field, text, fullCtx),
      ...ruleCrossToolShadowing(field, text, fullCtx),
      ...ruleEncodedPayload(field, text, fullCtx),
      ...ruleFakeTurnBoundary(field, text, fullCtx),
      ...rulePersistence(field, text, fullCtx),
    );
  }

  const all = normalizedParts.join('\n');
  findings.push(
    ...ruleParameterSmuggling(tool, all),
    ...ruleExcessivePermission(tool, all),
    ...ruleToolNameChecks(tool, fullCtx),
  );
  return dedupe(findings);
}

export function detectRugPull(current: ToolFingerprint[], previous: PreviousSnapshot | undefined): Finding[] {
  if (!previous) return [];
  const out: Finding[] = [];
  const prev = new Map(previous.fingerprints.map((p) => [p.name, p.hash]));
  const cur = new Map(current.map((c) => [c.name, c.hash]));
  for (const [name, hash] of cur) {
    const old = prev.get(name);
    if (old === undefined) {
      out.push({
        ruleId: 'rug-pull', severity: 'low', tool: name, location: 'tool',
        message: `New tool appeared since the scan at ${previous.scannedAt}.`,
        evidence: `sha256 ${hash.slice(0, 12)}`,
      });
    } else if (old !== hash) {
      out.push({
        ruleId: 'rug-pull', severity: 'high', tool: name, location: 'tool',
        message: `Tool definition changed since the approved scan at ${previous.scannedAt} (possible rug pull). Re-review before use.`,
        evidence: `sha256 ${old.slice(0, 12)} → ${hash.slice(0, 12)}`,
      });
    }
  }
  for (const name of prev.keys()) {
    if (!cur.has(name)) {
      out.push({
        ruleId: 'rug-pull', severity: 'info', tool: name, location: 'tool',
        message: `Tool was removed since the scan at ${previous.scannedAt}.`, evidence: name,
      });
    }
  }
  return out;
}

export function scanServer(server: McpServerDefinition, options: ScanOptions = {}): ScanResult {
  const now = options.now ?? (() => new Date());
  const tools = Array.isArray(server.tools) ? server.tools.filter((t) => t && typeof t.name === 'string') : [];
  const names = tools.map((t) => t.name);
  const external = (options.knownToolNames ?? []).filter((k) => k.server !== server.serverId);

  const findings: Finding[] = [];
  const fingerprints: ToolFingerprint[] = [];

  // Duplicate names inside one server are themselves suspicious.
  const counts = new Map<string, number>();
  for (const n of names) counts.set(n, (counts.get(n) ?? 0) + 1);
  for (const [n, c] of counts) {
    if (c > 1) {
      findings.push({
        ruleId: 'tool-name-collision', severity: 'medium', tool: n, location: 'name',
        message: `Tool name declared ${c} times on the same server.`, evidence: n,
      });
    }
  }

  for (const tool of tools) {
    findings.push(...scanTool(tool, { siblingNames: names, externalNames: external }));
    fingerprints.push(fingerprintTool(tool));
  }
  findings.push(...detectRugPull(fingerprints, options.previous));

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.tool.localeCompare(b.tool));
  const { maxSeverity, riskScore } = scoreFindings(findings);

  return {
    serverId: server.serverId,
    serverName: server.name ?? server.serverId,
    scannedAt: now().toISOString(),
    toolCount: tools.length,
    findings,
    maxSeverity,
    riskScore,
    fingerprints,
  };
}

/** Max severity and 0..100 risk score for a set of findings. */
export function scoreFindings(findings: Finding[]): { maxSeverity: Severity; riskScore: number } {
  const maxSeverity = findings.reduce<Severity>(
    (acc, x) => (SEVERITY_ORDER[x.severity] > SEVERITY_ORDER[acc] ? x.severity : acc),
    'info',
  );
  const riskScore = Math.min(100, findings.reduce((acc, x) => acc + SEVERITY_WEIGHT[x.severity], 0));
  return { maxSeverity, riskScore };
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((x) => {
    const k = `${x.ruleId}|${x.tool}|${x.location}|${x.severity}|${x.message}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Findings at or above a severity threshold. */
export function atLeast(findings: Finding[], min: Severity): Finding[] {
  return findings.filter((x) => SEVERITY_ORDER[x.severity] >= SEVERITY_ORDER[min]);
}
