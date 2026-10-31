/**
 * Guard rails: the app must not make network calls other than Atlassian product APIs.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = join(__dirname, '..');
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|tsx)$/.test(n) ? [p] : [];
  });
}
const sources = files(join(root, 'src')).map((p) => ({ p, src: readFileSync(p, 'utf8') }));

describe('no arbitrary network egress', () => {
  it('source never calls fetch / http clients directly', () => {
    for (const { p, src } of sources) {
      expect(src, p).not.toMatch(/\bfetch\s*\(|from ['"](node:)?(https?|net|axios|node-fetch|undici)['"]|XMLHttpRequest|invokeRemote/);
    }
  });
  it('only requestJira is used for outbound calls', () => {
    const outbound = sources.filter(({ src }) => /request(Jira|Confluence|Bitbucket)|asApp\(\)|asUser\(\)/.test(src));
    expect(outbound.map((s) => s.p.replace(root, ''))).toEqual(['/src/jira/client.ts']);
  });
  it('manifest declares no external fetch permissions', () => {
    const manifest = readFileSync(join(root, 'manifest.yml'), 'utf8');
    expect(manifest).not.toMatch(/^\s*external\s*:/m);
    expect(manifest).not.toMatch(/fetch\s*:\s*\n\s*backend/);
  });
  it('scanner core is pure (no Forge imports)', () => {
    for (const { p, src } of sources.filter((s) => s.p.includes('/scanner/'))) {
      expect(src, p).not.toMatch(/@forge\//);
    }
  });
});
