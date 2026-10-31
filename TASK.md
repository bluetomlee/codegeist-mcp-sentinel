# Task: Atlassian Codegeist 2026 entry — "MCP Sentinel" (Forge app)
Hackathon: https://codegeist2026.devpost.com (deadline Dec 22 2026). Target bonus prizes: "Best Agents - Rovo" and "Best app with Atlassian MCP" ($1500 x6 each). Category: Apps for Software Teams.
Idea: Rovo agent + reusable rovo:action/skill that audits MCP server tool definitions for tool-poisoning / prompt-injection (hidden instructions in descriptions, exfil URLs, cross-tool shadowing, unicode/zero-width tricks, excessive permissions, rug-pull = description hash changed since last scan). Findings stored in Forge storage and optionally filed as Jira issues; a Jira project page (jira:projectPage, UI Kit) dashboard listing scanned servers + severity. Also expose the scanner via a Forge MCP server module if Forge supports it (check current Forge docs via web; if module unavailable, document clearly).
Reuse detection ideas from ~/work/odin-harness (payloads/, target/mcp_registry.json) — port heuristics to TypeScript, no copying secrets.
Requirements:
- Forge app structure (manifest.yml, src/), TypeScript, @forge/api, @forge/resolver, @forge/kvs or storage, UI Kit.
- Pure scanner core in src/scanner/ with vitest tests (>=25 cases incl. benign controls, false-positive checks).
- No network egress except Atlassian APIs; never fetch arbitrary URLs.
- README: problem, architecture, install (forge register/deploy/install — Kevin will do these; do NOT run forge login/deploy), demo script for <5min video, how it meets Forge+Rovo+MCP requirements. LICENSE MIT.
- Do not run any command that logs in, deploys, publishes or pushes. npm install + tests + lint + npm audit only.
Write RESULT.md at end: what works, test output summary, gaps.
