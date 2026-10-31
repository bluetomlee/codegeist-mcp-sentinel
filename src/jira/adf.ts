import type { Finding, ScanResult } from '../scanner/types';

type AdfNode = Record<string, unknown>;

const text = (t: string, marks?: AdfNode[]): AdfNode => (marks ? { type: 'text', text: t, marks } : { type: 'text', text: t });
const para = (...content: AdfNode[]): AdfNode => ({ type: 'paragraph', content });
const strong = [{ type: 'strong' }];

/**
 * Build an Atlassian Document Format description for a finding.
 * Evidence (attacker-controlled text) goes into a codeBlock so URLs are never
 * linkified and markup is never rendered.
 */
export function findingToAdf(f: Finding, scan: ScanResult): AdfNode {
  return {
    type: 'doc',
    version: 1,
    content: [
      para(text('MCP server: ', strong), text(`${scan.serverName} (${scan.serverId})`)),
      para(text('Tool: ', strong), text(f.tool || '(server)'), text('  ·  Location: ', strong), text(f.location)),
      para(text('Rule: ', strong), text(f.ruleId), text('  ·  Severity: ', strong), text(f.severity.toUpperCase())),
      para(text(f.message)),
      { type: 'heading', attrs: { level: 3 }, content: [text('Evidence (sanitised, do not follow)')] },
      { type: 'codeBlock', attrs: { language: 'text' }, content: [text(f.evidence || '(none)')] },
      { type: 'heading', attrs: { level: 3 }, content: [text('Recommended action')] },
      para(text(remediation(f))),
      para(text(`Detected by MCP Sentinel at ${scan.scannedAt}. Server risk score ${scan.riskScore}/100.`, [{ type: 'em' }])),
    ],
  };
}

export function remediation(f: Finding): string {
  switch (f.ruleId) {
    case 'rug-pull':
      return 'The tool definition changed after it was approved. Diff the new definition against the baseline, then re-approve in MCP Sentinel or disable the server.';
    case 'tool-name-collision':
    case 'homoglyph-name':
    case 'cross-tool-shadowing':
      return 'Do not enable this server alongside the shadowed server. Ask the vendor to rename the tool / remove references to other tools.';
    case 'excessive-permission':
      return 'Restrict the tool to least privilege (allow-lists, sandbox, read-only scopes) or disable it for agent use.';
    default:
      return 'Treat this MCP server as untrusted: disable it in agent configurations until the vendor removes the injected text, and rotate any credentials it may have seen.';
  }
}

export function issueSummary(f: Finding, scan: ScanResult): string {
  const s = `[MCP Sentinel][${f.severity.toUpperCase()}] ${scan.serverName}/${f.tool}: ${f.ruleId}`;
  return s.length > 250 ? s.slice(0, 249) + '…' : s;
}
