# RESULT: MCP Sentinel (Codegeist 2026)

Date: 2026-11-01. Everything below was run locally. I did **not** run any login, register, deploy, install,
publish or push command. Nothing has been committed to git.

## What works (verified locally)

| Area | Status |
|---|---|
| Pure TS scanner (`src/scanner/`): 16 rule IDs, Unicode normalisation and tag decoding, base64/hex/ROT13/leetspeak decoding, SHA-256 fingerprints, rug-pull diff, risk score | ✅ 113 tests passing |
| Detection on the odin-harness-derived corpus | ✅ **38/38 malicious detected** (≥ medium); **7/7 benign controls clean** (nothing ≥ low) |
| False-positive controls | ✅ 4 realistic benign servers (GitHub-, filesystem-, weather- and vault-style), emoji/accents, commit SHAs/UUIDs, "you must provide…", password-reset wording, infra tokens (S3/EC2/v2/MD5) all produce 0 findings ≥ low |
| Service layer (scan → store → baseline → rug-pull → approve; cross-server shadowing; Jira filing with dedupe) | ✅ tested with an in-memory store and a fake Jira |
| Forge manifest: `rovo:agent`, 5 `action`s, `rovo:mcp`, `jira:projectPage` (UI Kit, `render: native`), functions, resources | ✅ passes **full** offline validation with `@forge/manifest` 13.8 (`npm run validate:manifest`) |
| TypeScript strict typecheck (backend + UI Kit frontend) | ✅ `tsc --noEmit` clean |
| ESLint (typescript-eslint recommended) | ✅ clean |
| `npm audit` | ✅ 0 vulnerabilities (after `overrides` for transitive `prosemirror-view`, `glob`, `minimatch`). I checked that eslint and manifest validation still work with the overrides. |
| No egress except Atlassian APIs | ✅ enforced by `tests/egress.test.ts` (no `fetch`/http/net/`invokeRemote`; only `src/jira/client.ts` calls `requestJira`; no `permissions.external`) |
| README (problem, architecture, install, under-5-min demo script, requirements mapping), LICENSE (MIT) | ✅ |

### Test output summary

```text
$ npm run check
> tsc --noEmit                        (clean)
> eslint src tests                    (clean)
> node scripts/validate-manifest.cjs  manifest.yml is valid
> vitest run
 Test Files  5 passed (5)
      Tests  113 passed (113)
$ npm audit
found 0 vulnerabilities
```

Per file: `scanner.test.ts` 54 · `corpus.test.ts` 46 (38 malicious + 7 benign + 1 rate) · `service.test.ts` 8 ·
`egress.test.ts` 4 · `demo.test.ts` 1.

## Forge MCP module: availability

According to current docs, `rovo:mcp` exists and is labelled **Preview** (it was in EAP earlier). Each app may have
one, and it exposes `action` keys as MCP tools to Rovo Studio agents. Exposure to *external* MCP clients is
**disabled by default** and must be enabled per installation by a site/org admin. The manifest declares it, and the
bundled `@forge/manifest` schema accepts it. If the deploy-time platform rejects it (for example, Preview gating on
the dev site), delete the `rovo:mcp` block. The agent, actions and project page do not depend on it.

## Gaps and things to check on deploy (not verifiable offline)

1. **Not deployed or run on a real site.** Behaviour inside Forge (KVS, `requestJira`, UI Kit rendering, Rovo action
   invocation) is untested in the real runtime. Only the pure logic is tested, with mocks. First `forge deploy` may
   surface issues the offline validator can't catch.
2. **Rovo action payload shape.** Handlers read inputs from `payload.<input>` and Jira context from
   `payload.context.jira.projectKey`, and the approver's account ID from `context.principal.accountId` /
   `context.accountId`. Check these in `forge logs` and adjust `src/index.ts` if needed. The project key can also be
   passed explicitly, so filing works either way.
3. **Large `toolsJson` through Rovo.** The agent must pass the pasted JSON verbatim as a string input. Very large
   tool lists may be truncated or rewritten by the LLM. The project page form is the reliable path for big servers
   (512 KiB cap).
4. **UI Kit details.** `DynamicTable`, `Select`, `CodeBlock` and `useForm` usage typechecks against `@forge/react`
   12.4, but layout and props haven't been seen rendered. Expect small cosmetic tweaks.
5. **Jira issue type.** The app picks *Bug*, then *Task*, then the first non-subtask type via `createmeta`.
   Team-managed projects with custom required fields may reject creation. The error is surfaced to the user.
6. **`app.id`** is a placeholder until `forge register`. The runtime is set to `nodejs22.x`. Switch to a newer
   runtime if `forge lint` suggests one.
7. **Heuristic limits.** Detection is regex/heuristic, not semantic. Paraphrased injections without trigger
   vocabulary, or in other languages besides English and Chinese, can slip through. Sophisticated benign text (for
   example, a security tool that *describes* injection phrases) can trigger findings. An optional LLM second opinion
   (via the Rovo agent itself, already prompted to explain findings) is the natural next step.
8. Rug-pull detection needs the user to re-paste `tools/list`. There's no scheduled re-scan, because the app never
   connects to MCP servers by design (no egress).
9. `forge lint` (CLI) wasn't run because the Forge CLI isn't installed here. `npm run validate:manifest` uses the same
   `@forge/manifest` validators offline.

## Next steps for Kevin

```bash
npm install && npm run check
npm i -g @forge/cli && forge login && forge register
forge deploy && forge install --product jira --site <site>.atlassian.net
forge logs   # while exercising the agent, to confirm payload shapes (gap 2)
```

Then record the demo following the README script, using `fixtures/demo/1-…`, `2-…` and `3-…` in order.
