/** The demo-video fixtures must behave exactly as the README demo script says. */
import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
vi.mock('@forge/api', () => ({ default: {}, route: () => '' }));
import { MemoryScanStore } from '../src/storage/store';
import { approveBaseline, listServers, scanAndStore, type Deps } from '../src/service';

const read = (f: string) => readFileSync(join(__dirname, '../fixtures/demo', f), 'utf8');

describe('demo script', () => {
  it('clean → poisoned → rug pull → approve', async () => {
    const deps: Deps = { store: new MemoryScanStore(), jira: { createIssue: async () => 'X-1' } };

    const clean = await scanAndStore(deps, { serverId: 'github-mcp', serverName: 'GitHub MCP', toolsJson: read('1-github-clean.json') });
    expect(clean.result.riskScore).toBe(0);

    const evil = await scanAndStore(deps, { serverId: 'weather-mcp', serverName: 'Weather MCP', toolsJson: read('2-weather-poisoned.json') });
    expect(evil.result.maxSeverity).toBe('critical');
    const rules = new Set(evil.result.findings.map((f) => f.ruleId));
    for (const r of ['hidden-instruction', 'concealment', 'sensitive-file', 'parameter-smuggling', 'cross-tool-shadowing', 'exfil-url', 'homoglyph-name', 'tool-name-collision']) {
      expect(rules, r).toContain(r);
    }

    const rug = await scanAndStore(deps, { serverId: 'github-mcp', toolsJson: read('3-github-rugpull.json') });
    expect(rug.result.findings.find((f) => f.ruleId === 'rug-pull')).toMatchObject({ tool: 'create_issue', severity: 'high' });
    expect(rug.result.findings.some((f) => f.ruleId === 'concealment')).toBe(true);

    expect((await listServers(deps)).map((s) => s.serverId)).toEqual(['weather-mcp', 'github-mcp']);
    await approveBaseline(deps, 'github-mcp');
    expect((await listServers(deps)).find((s) => s.serverId === 'github-mcp')?.rugPull).toBe(false);
  });
});
