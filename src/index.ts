/**
 * Forge entry points.
 *
 *  - Rovo actions (also exposed as MCP tools via the rovo:mcp module):
 *      scanMcpServerAction, listScannedServersAction, getServerFindingsAction,
 *      fileJiraIssuesAction, approveBaselineAction
 *  - UI Kit resolver for the Jira project page: handler
 */
import Resolver from '@forge/resolver';
import { ParseError, formatFindingsMarkdown, summarizeResult } from './scanner';
import { KvsScanStore } from './storage/kvs-store';
import { toSummary } from './storage/store';
import { ForgeJiraClient } from './jira/client';
import {
  UserInputError,
  approveBaseline,
  deleteServer,
  fileJiraIssues,
  getServer,
  listServers,
  scanAndStore,
  type Deps,
} from './service';

const deps = (): Deps => ({ store: new KvsScanStore(), jira: new ForgeJiraClient() });

/** Shape of a Rovo action payload: declared inputs + product context. */
interface ActionPayload {
  [input: string]: unknown;
  context?: { jira?: { projectKey?: string; issueKey?: string }; [k: string]: unknown };
}
interface ActionContext {
  accountId?: string;
  principal?: { accountId?: string };
}

function errorMessage(e: unknown): string {
  if (e instanceof UserInputError || e instanceof ParseError) return e.message;
  console.error('MCP Sentinel action failed', e);
  return 'MCP Sentinel hit an internal error. Check the app logs (forge logs).';
}

async function run(fn: () => Promise<string>): Promise<string> {
  try {
    return await fn();
  } catch (e) {
    return `Error: ${errorMessage(e)}`;
  }
}

// ---------------------------------------------------------------------------
// Rovo actions / MCP tools. They return Markdown text the agent can relay.
// ---------------------------------------------------------------------------

export const scanMcpServerAction = (payload: ActionPayload): Promise<string> =>
  run(async () => {
    const res = await scanAndStore(deps(), {
      serverId: String(payload.serverId ?? ''),
      serverName: payload.serverName ? String(payload.serverName) : undefined,
      toolsJson: String(payload.toolsJson ?? ''),
    });
    const note = res.baselineCreated
      ? '\n\n_First scan of this server: tool fingerprints saved as the trusted baseline for rug-pull detection._'
      : '';
    return `${res.report}${note}`;
  });

export const listScannedServersAction = (): Promise<string> =>
  run(async () => {
    const servers = await listServers(deps());
    if (!servers.length) return 'No MCP servers have been scanned yet.';
    const rows = servers.map(
      (s) =>
        `| ${s.serverName} (\`${s.serverId}\`) | ${s.toolCount} | ${s.riskScore} | ${s.maxSeverity}${s.rugPull ? ' ⚠\uFE0F rug-pull' : ''} | ${s.findingCount} | ${s.scannedAt} | ${s.jiraIssues.join(', ') || '-'} |`,
    );
    return ['| Server | Tools | Risk | Max severity | Findings | Last scan | Jira |', '|---|---|---|---|---|---|---|', ...rows].join('\n');
  });

export const getServerFindingsAction = (payload: ActionPayload): Promise<string> =>
  run(async () => {
    const rec = await getServer(deps(), payload.serverId);
    return formatFindingsMarkdown(rec.lastScan, 50);
  });

export const fileJiraIssuesAction = (payload: ActionPayload): Promise<string> =>
  run(async () => {
    const projectKey = payload.projectKey ?? payload.context?.jira?.projectKey;
    const res = await fileJiraIssues(deps(), { serverId: payload.serverId, projectKey, minSeverity: payload.minSeverity });
    const lines = [
      res.created.length
        ? `Created ${res.created.length} Jira issue(s): ${res.created.map((c) => c.key).join(', ')}`
        : 'No new Jira issues created.',
    ];
    if (res.skippedAlreadyFiled) lines.push(`${res.skippedAlreadyFiled} finding(s) were already filed earlier.`);
    if (res.errors.length) lines.push(`Errors: ${res.errors.join('; ')}`);
    return lines.join('\n');
  });

export const approveBaselineAction = (payload: ActionPayload, context?: ActionContext): Promise<string> =>
  run(async () => {
    const rec = await approveBaseline(deps(), payload.serverId, context?.principal?.accountId ?? context?.accountId);
    return `Baseline for ${rec.serverName} approved (${rec.baseline.fingerprints.length} tools). Future scans will report changes against this version.`;
  });

// ---------------------------------------------------------------------------
// UI Kit resolver (Jira project page)
// ---------------------------------------------------------------------------

const resolver = new Resolver();

type Ok<T> = { ok: true; data: T };
type Err = { ok: false; error: string };
async function wrap<T>(fn: () => Promise<T>): Promise<Ok<T> | Err> {
  try {
    return { ok: true, data: await fn() };
  } catch (e) {
    return { ok: false, error: errorMessage(e) };
  }
}

resolver.define('listServers', () => wrap(() => listServers(deps())));

resolver.define('getServer', ({ payload }) =>
  wrap(async () => {
    const rec = await getServer(deps(), (payload as { serverId?: string }).serverId);
    return { summary: toSummary(rec), findings: rec.lastScan.findings, baseline: rec.baseline, filedIssues: rec.filedIssues };
  }),
);

resolver.define('scan', ({ payload }) =>
  wrap(async () => {
    const p = payload as { serverId?: string; serverName?: string; toolsJson?: string };
    const res = await scanAndStore(deps(), {
      serverId: p.serverId ?? '',
      serverName: p.serverName,
      toolsJson: p.toolsJson ?? '',
    });
    return { summary: summarizeResult(res.result), baselineCreated: res.baselineCreated, serverId: res.result.serverId };
  }),
);

resolver.define('fileIssues', ({ payload, context }) =>
  wrap(async () => {
    const p = payload as { serverId?: string; minSeverity?: string; projectKey?: string };
    const ext = (context as { extension?: { project?: { key?: string } } }).extension;
    return fileJiraIssues(deps(), {
      serverId: p.serverId,
      projectKey: p.projectKey ?? ext?.project?.key,
      minSeverity: p.minSeverity,
    });
  }),
);

resolver.define('approveBaseline', ({ payload, context }) =>
  wrap(async () => {
    const rec = await approveBaseline(deps(), (payload as { serverId?: string }).serverId, context.accountId);
    return toSummary(rec);
  }),
);

resolver.define('deleteServer', ({ payload }) =>
  wrap(() => deleteServer(deps(), (payload as { serverId?: string }).serverId)),
);

export const handler = resolver.getDefinitions();
