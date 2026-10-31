import type { ScanResult } from './types';

const ICON: Record<string, string> = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜' };

export function summarizeResult(r: ScanResult): string {
  const counts: Record<string, number> = {};
  for (const x of r.findings) counts[x.severity] = (counts[x.severity] ?? 0) + 1;
  const parts = ['critical', 'high', 'medium', 'low', 'info'].filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);
  return `${r.serverName}: ${r.toolCount} tools, risk ${r.riskScore}/100, max severity ${r.maxSeverity}` +
    (parts.length ? ` (${parts.join(', ')})` : ' (no findings)');
}

/** Markdown report suitable for a Rovo chat reply or a Jira description. */
export function formatFindingsMarkdown(r: ScanResult, limit = 25): string {
  const lines = [`**${summarizeResult(r)}**`, ''];
  const shown = r.findings.filter((x) => x.severity !== 'info').slice(0, limit);
  if (!shown.length) {
    lines.push('No actionable findings.');
  } else {
    lines.push('| Sev | Tool | Rule | Finding | Evidence |', '|---|---|---|---|---|');
    for (const x of shown) {
      lines.push(`| ${ICON[x.severity]} ${x.severity} | \`${esc(x.tool)}\` | ${x.ruleId} | ${esc(x.message)} | \`${esc(x.evidence).slice(0, 120)}\` |`);
    }
    const hidden = r.findings.filter((x) => x.severity !== 'info').length - shown.length;
    if (hidden > 0) lines.push('', `…and ${hidden} more.`);
  }
  return lines.join('\n');
}

function esc(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/`/g, "'").replace(/\n/g, ' ');
}
