import api, { route } from '@forge/api';

export interface CreateIssueInput {
  projectKey: string;
  summary: string;
  description: Record<string, unknown>;
  labels: string[];
}

export interface JiraClient {
  createIssue(input: CreateIssueInput): Promise<string>;
}

const PROJECT_KEY_RE = /^[A-Z][A-Z0-9_]{0,9}$/;

export function isValidProjectKey(key: string): boolean {
  return PROJECT_KEY_RE.test(key);
}

/**
 * Jira REST client running as the invoking user (so Jira permissions apply).
 * Only calls Atlassian product APIs via @forge/api — no other egress.
 */
export class ForgeJiraClient implements JiraClient {
  private issueTypeCache = new Map<string, string>();

  private async pickIssueType(projectKey: string): Promise<string> {
    const cached = this.issueTypeCache.get(projectKey);
    if (cached) return cached;
    const res = await api.asUser().requestJira(route`/rest/api/3/issue/createmeta/${projectKey}/issuetypes`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`Cannot read issue types for ${projectKey}: HTTP ${res.status}`);
    const body = (await res.json()) as { issueTypes?: Array<{ id: string; name: string; subtask: boolean }> };
    const types = (body.issueTypes ?? []).filter((t) => !t.subtask);
    const pick = types.find((t) => /^bug$/i.test(t.name)) ?? types.find((t) => /^task$/i.test(t.name)) ?? types[0];
    if (!pick) throw new Error(`Project ${projectKey} has no usable issue types.`);
    this.issueTypeCache.set(projectKey, pick.id);
    return pick.id;
  }

  async createIssue(input: CreateIssueInput): Promise<string> {
    if (!isValidProjectKey(input.projectKey)) throw new Error(`Invalid Jira project key "${input.projectKey}".`);
    const issueTypeId = await this.pickIssueType(input.projectKey);
    const res = await api.asUser().requestJira(route`/rest/api/3/issue`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fields: {
          project: { key: input.projectKey },
          issuetype: { id: issueTypeId },
          summary: input.summary,
          description: input.description,
          labels: input.labels,
        },
      }),
    });
    if (!res.ok) {
      const detail = await res.text();
      throw new Error(`Jira issue creation failed: HTTP ${res.status} ${detail.slice(0, 300)}`);
    }
    const created = (await res.json()) as { key: string };
    return created.key;
  }
}
