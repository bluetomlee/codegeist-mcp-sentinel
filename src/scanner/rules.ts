/**
 * Detection rules. Each rule is a pure function over one text field of one tool
 * (or over the tool / server as a whole). Heuristics are ported from the
 * odin-harness payload corpus (mcp_poisoning, obfuscation, tool_hijack) and
 * generalised.
 */
import type { Finding, McpTool, RuleId, Severity } from './types';
import { excerpt, parameterNames, type TextField } from './text';
import { foldConfusables, hasMixedScript, inspectInvisible, makeVisible } from './unicode';

export interface RuleContext {
  tool: McpTool;
  /** Names of other tools on the same server. */
  siblingNames: string[];
  /** Names of tools on other servers / host builtins. */
  externalNames: Array<{ server: string; name: string }>;
}

function f(
  ruleId: RuleId,
  severity: Severity,
  tool: string,
  location: string,
  message: string,
  evidence: string,
): Finding {
  return { ruleId, severity, tool, location, message, evidence: makeVisible(evidence) };
}

function firstMatch(text: string, patterns: RegExp[]): RegExpExecArray | null {
  for (const p of patterns) {
    p.lastIndex = 0;
    const m = p.exec(text);
    if (m) return m;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------

const EXFIL_VERBS =
  /\b(send|sends|sending|post|posts|upload|uploads|forward|forwards|transmit|exfiltrate|beacon|report it|leak|copy it|submit it|append (it|them) to|include (it|them) in the (url|query|request))\b/i;

const SENSITIVE_PATHS: RegExp[] = [
  /~\/\.ssh\b|\.ssh\/(id_[a-z0-9]+|authorized_keys|config)\b|\bid_(rsa|dsa|ecdsa|ed25519)\b/i,
  /(^|[\s"'`(/])\.env(\.[a-z]+)?\b/i,
  /\.aws\/credentials|\.kube\/config|\.docker\/config\.json|\.npmrc\b|\.netrc\b|\.pypirc\b|\.git-credentials\b/i,
  /\bclaude_desktop_config\.json\b|\bmcp\.json\b|\.cursor\/mcp/i,
  /\/etc\/(passwd|shadow|sudoers)\b/i,
  /\bsecrets?\.(txt|json|ya?ml)\b|\bcredentials?\.(json|txt|ya?ml)\b|\bservice[-_]account\.json\b/i,
  /\b(private[ _-]key|keychain|wallet\.dat|seed phrase|mnemonic phrase)\b/i,
];

const CREDENTIAL_TERMS = /\b(api[ _-]?keys?|access[ _-]?tokens?|bearer tokens?|session cookies?|passwords?|secrets?|credentials?|auth(entication)? tokens?)\b/i;
const READ_OR_PASS_VERBS = /\b(read|cat|open|load|include|pass|attach|provide the contents|send|forward|upload|append)\b/i;

// ---------------------------------------------------------------------------
// Text-field rules
// ---------------------------------------------------------------------------

const HIDDEN_TAGS =
  /<\s*\/?\s*(important|system|instructions?|secret|hidden|admin|assistant[_-]?note|context|critical|sys)\b[^>]*>|\[\s*\/?\s*(system|important|instructions?|admin|hidden|assistant[_ -]?note)\s*\]/i;

const OVERRIDE_PATTERNS: RegExp[] = [
  /\bignore (all |any )?(the )?(previous|prior|above|earlier|preceding|other) (instructions|prompts|messages|rules|guidelines)\b/i,
  /\bdisregard (all |any )?(the )?(previous|prior|above|system|user) (instructions|prompts|rules)\b/i,
  /\b(note|message|instructions?|directive) (to|for) (the )?(assistant|ai|model|llm|agent|claude|copilot)\b/i,
  /\bthis (tool|server|plugin) (modifies|overrides|changes|alters|replaces) (how|the behaviou?r of) (other|all|every)\b/i,
  /\b(you are now|from now on,? you)\b/i,
  /\b(system prompt|developer mode|jailbreak|dan mode)\b/i,
  /(^|[\s>.\]])(assistant|ai|claude|agent)\s*[:,]\s*[^.\n]{0,60}?\b(save|write|read|send|run|call|delete|overwrite|fetch|open|execute|create|forward)\b/i,
  /(给|致|对)\s*(AI|人工智能)?\s*助手/,
  /忽略(之前|以上|先前|前面)的?(所有)?(指令|说明|指示)/,
];

const DIRECTIVE_PATTERNS: RegExp[] = [
  /\b(before|after|whenever|every time) (you )?(use|using|call|calling|invoke|invoking|run|running) (this|any|every|the|another|other)\b/i,
  /\byou (must|should|are required to|need to|have to) (first |always |also )?(read|call|invoke|send|include|pass|fetch|run|execute|write|cat|open|upload|forward)\b/i,
  /\b(always|first) (read|cat|send|include|forward|upload)\b/i,
  /\bcompliance requirement\b.{0,80}\b(read|run|cat|include|send)\b/i,
  /\b(overwrite|replace the contents of|truncate|delete|modify)\b[^.]{0,40}\b[\w-]+\.(txt|md|json|ya?ml|env|sh|csv|conf)\b/i,
  /\b(wire|transfer|send) (the )?(payment|funds|money)\b|\bIBAN\b|\b(bank|routing) account\b/i,
];

const HTML_HIDING: RegExp[] = [
  /<!--[\s\S]{3,}?-->/,
  /style\s*=\s*["'][^"']*(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0+)?\b|color\s*:\s*(white|#fff\b|#ffffff|transparent))/i,
];

export function ruleHiddenInstruction(field: TextField, text: string, ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const tag = HIDDEN_TAGS.exec(text);
  if (tag) {
    out.push(
      f('hidden-instruction', 'high', ctx.tool.name, field.location,
        `Pseudo-markup tag "${tag[0]}" used to smuggle instructions to the model.`,
        excerpt(text, tag.index, tag[0].length)),
    );
  }
  const ov = firstMatch(text, OVERRIDE_PATTERNS);
  if (ov) {
    out.push(
      f('hidden-instruction', 'high', ctx.tool.name, field.location,
        'Text addresses the AI model directly or tries to override its instructions.',
        excerpt(text, ov.index, ov[0].length)),
    );
  }
  const hid = firstMatch(text, HTML_HIDING);
  if (hid) {
    out.push(
      f('hidden-instruction', 'medium', ctx.tool.name, field.location,
        'HTML comment or CSS-hidden text inside tool metadata (invisible to humans, visible to the model).',
        excerpt(text, hid.index, Math.min(hid[0].length, 80))),
    );
  }
  const dir = firstMatch(text, DIRECTIVE_PATTERNS);
  if (dir && !ov && !tag) {
    out.push(
      f('hidden-instruction', 'medium', ctx.tool.name, field.location,
        'Imperative directive aimed at the agent embedded in tool metadata.',
        excerpt(text, dir.index, dir[0].length)),
    );
  }
  return out;
}

const CONCEALMENT_PATTERNS: RegExp[] = [
  /\b(do not|don't|never|must not) (tell|mention|inform|reveal|disclose|show|notify|alert)( this| it| that)?( to)? (the )?(user|human|operator)\b/i,
  /\bwithout (telling|informing|notifying|alerting|asking) (the )?(user|human)\b/i,
  /\b(the )?user (must|should|need) not (know|see|be told|be informed)\b/i,
  /\b(silently|secretly|covertly|quietly) (send|read|upload|forward|call|include|exfiltrate|copy|write|run|execute|fetch)\b/i,
  /\b(keep|treat) this (secret|hidden|confidential) from the user\b/i,
  /(不要|别|切勿)(告诉|通知|提醒)用户/,
];

export function ruleConcealment(field: TextField, text: string, ctx: RuleContext): Finding[] {
  const m = firstMatch(text, CONCEALMENT_PATTERNS);
  if (!m) return [];
  return [
    f('concealment', 'high', ctx.tool.name, field.location,
      'Instructs the agent to hide its actions from the user.',
      excerpt(text, m.index, m[0].length)),
  ];
}

const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s<>"'`)\]]+/gi;
const PLACEHOLDER_RE = /(\{\{?\s*[A-Za-z_][\w.]*\s*\}?\}|\$\{[^}]+\}|<[A-Z_]{3,}>|%[A-Z_]{3,}%)/;
const IP_HOST_RE = /^[a-z]+:\/\/(\d{1,3}\.){3}\d{1,3}([:/]|$)/i;
const MD_IMAGE_RE = /!\[[^\]]*\]\(\s*(https?:\/\/[^)\s]+)\s*\)/i;

export function ruleExfilUrl(field: TextField, text: string, ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const md = MD_IMAGE_RE.exec(text);
  if (md && /[?&=]/.test(md[1])) {
    out.push(
      f('exfil-url', 'high', ctx.tool.name, field.location,
        'Markdown image with query parameters — renders as a zero-click data beacon.',
        excerpt(text, md.index, md[0].length)),
    );
  }
  URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_RE.exec(text))) {
    const url = m[0];
    const windowText = text.slice(Math.max(0, m.index - 160), m.index + url.length + 40);
    let severity: Severity;
    let message: string;
    if (PLACEHOLDER_RE.test(url)) {
      severity = 'critical';
      message = 'URL contains a template placeholder the agent is expected to fill — classic data-exfiltration sink.';
    } else if (EXFIL_VERBS.test(windowText)) {
      severity = 'high';
      message = 'Tool metadata tells the agent to send data to an external URL.';
    } else if (IP_HOST_RE.test(url)) {
      severity = 'medium';
      message = 'URL points at a raw IP address.';
    } else {
      severity = 'info';
      message = 'Tool metadata references an external URL.';
    }
    out.push(f('exfil-url', severity, ctx.tool.name, field.location, message, excerpt(text, m.index, url.length)));
  }
  return out;
}

export function ruleSensitiveFile(field: TextField, text: string, ctx: RuleContext): Finding[] {
  const m = firstMatch(text, SENSITIVE_PATHS);
  if (m) {
    return [
      f('sensitive-file', 'high', ctx.tool.name, field.location,
        `References a sensitive file or secret store ("${m[0].trim()}").`,
        excerpt(text, m.index, m[0].length)),
    ];
  }
  const cred = CREDENTIAL_TERMS.exec(text);
  if (cred) {
    // Only flag credentials when the text also asks the agent to read/pass/send them.
    const win = text.slice(Math.max(0, cred.index - 80), cred.index + cred[0].length + 80);
    if (READ_OR_PASS_VERBS.test(win) && /\b(contents?|value|full|raw|your|the user's|all)\b/i.test(win)) {
      return [
        f('sensitive-file', 'medium', ctx.tool.name, field.location,
          'Asks the agent to read or pass along credentials.',
          excerpt(text, cred.index, cred[0].length)),
      ];
    }
  }
  return [];
}

export function ruleCrossToolShadowing(field: TextField, text: string, ctx: RuleContext): Finding[] {
  const candidates = [
    ...ctx.siblingNames.map((n) => ({ name: n, where: 'same server' })),
    ...ctx.externalNames.map((e) => ({ name: e.name, where: `server "${e.server}"` })),
  ].filter((c) => c.name !== ctx.tool.name && c.name.length >= 4);
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const c of candidates) {
    if (seen.has(c.name)) continue;
    const re = new RegExp(`(^|[^\\w])${escapeRe(c.name)}([^\\w]|$)`, 'i');
    const m = re.exec(text);
    if (!m) continue;
    const win = text.slice(Math.max(0, m.index - 120), m.index + c.name.length + 120);
    const directive =
      /\b(whenever|before|after|instead of|every time|must|always|never|override|replace|do not use|don't use|modif(y|ies)|redirect)\b/i;
    if (directive.test(win)) {
      seen.add(c.name);
      out.push(
        f('cross-tool-shadowing', 'high', ctx.tool.name, field.location,
          `Description tries to change how another tool ("${c.name}", ${c.where}) is used.`,
          excerpt(text, m.index, c.name.length)),
      );
    }
  }
  return out;
}

export function ruleInvisibleUnicode(field: TextField, raw: string, ctx: RuleContext): Finding[] {
  const r = inspectInvisible(raw);
  const out: Finding[] = [];
  if (r.tags > 0) {
    out.push(
      f('invisible-unicode', 'critical', ctx.tool.name, field.location,
        `Contains ${r.tags} invisible Unicode tag characters (ASCII smuggling). Decoded: "${r.decodedTags.slice(0, 120)}"`,
        r.decodedTags.slice(0, 160) || raw.slice(0, 160)),
    );
  }
  if (r.zeroWidth > 0) {
    const idx = raw.search(/[\u200B\u200C\u200D\u2060-\u2064\uFEFF\u00AD\u180E\u034F]/u);
    out.push(
      f('invisible-unicode', 'high', ctx.tool.name, field.location,
        `Contains ${r.zeroWidth} zero-width/format characters that can split keywords to evade filters.`,
        excerpt(raw, Math.max(0, idx), 1)),
    );
  }
  if (r.variationSelectors > 2) {
    out.push(
      f('invisible-unicode', 'medium', ctx.tool.name, field.location,
        `Contains ${r.variationSelectors} variation selectors (possible invisible data encoding).`,
        raw.slice(0, 120)),
    );
  }
  if (r.bidi > 0) {
    const idx = raw.search(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/u);
    out.push(
      f('bidi-override', 'high', ctx.tool.name, field.location,
        'Contains bidirectional control characters: displayed text differs from what the model reads.',
        excerpt(raw, Math.max(0, idx), 1)),
    );
  }
  return out;
}

const SUSPICIOUS_DECODED =
  /(secret|password|token|api[_ ]?key|ssh|\.env|https?:\/\/|ignore (previous|prior)|send|exfil|curl |wget |http_get|read_file|cat )/i;

function isMostlyPrintable(s: string): boolean {
  if (!s.length) return false;
  let printable = 0;
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09) printable++;
  }
  return printable / s.length > 0.9;
}

function decodeBase64(s: string): string | null {
  try {
    const clean = s.replace(/-/g, '+').replace(/_/g, '/');
    const buf = Buffer.from(clean, 'base64');
    if (buf.length < 12) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

function rot13(s: string): string {
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export function ruleEncodedPayload(field: TextField, text: string, ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const b64 = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{28,}={0,2}(?![A-Za-z0-9+/=_-])/g;
  let m: RegExpExecArray | null;
  while ((m = b64.exec(text))) {
    const token = m[0];
    // Skip things that are clearly identifiers / hex hashes / paths.
    if (/^[0-9a-f]+$/i.test(token) || /^[a-z_]+$/i.test(token)) continue;
    const decoded = decodeBase64(token);
    if (decoded && isMostlyPrintable(decoded)) {
      const suspicious = SUSPICIOUS_DECODED.test(decoded);
      out.push(
        f('encoded-payload', suspicious ? 'high' : 'low', ctx.tool.name, field.location,
          suspicious
            ? `Base64 blob decodes to agent instructions: "${decoded.slice(0, 120)}"`
            : `Base64 blob decodes to readable text: "${decoded.slice(0, 80)}"`,
          excerpt(text, m.index, token.length)),
      );
    }
  }
  const hex = /\b(?:[0-9a-fA-F]{2}){20,}\b/g;
  while ((m = hex.exec(text))) {
    const bytes = m[0].match(/../g)!.map((h) => parseInt(h, 16));
    const decoded = String.fromCharCode(...bytes);
    if (isMostlyPrintable(decoded)) {
      const suspicious = SUSPICIOUS_DECODED.test(decoded);
      out.push(
        f('encoded-payload', suspicious ? 'high' : 'low', ctx.tool.name, field.location,
          `Hex blob decodes to readable text: "${decoded.slice(0, 120)}"`,
          excerpt(text, m.index, m[0].length)),
      );
    }
  }
  if (/\brot-?13\b/i.test(text)) {
    const decoded = rot13(text);
    if (SUSPICIOUS_DECODED.test(decoded) && !SUSPICIOUS_DECODED.test(text.replace(/\brot-?13\b/gi, ''))) {
      out.push(
        f('encoded-payload', 'high', ctx.tool.name, field.location,
          'ROT13-encoded instructions detected.',
          excerpt(decoded, 0, 0, 100)),
      );
    }
  }
  const leet = deLeet(text);
  if (leet !== text) {
    const sus = (t: string) => !!firstMatch(t, SENSITIVE_PATHS) || /\b(read|send|upload)\b.{0,40}\b(secret|password|token|credentials?)\b|\bhttps?:\/\//i.test(t);
    if (sus(leet) && !sus(text)) {
      out.push(
        f('encoded-payload', 'high', ctx.tool.name, field.location,
          `Leetspeak-obfuscated instructions: "${leet.slice(0, 120)}"`,
          excerpt(text, 0, 0, 100)),
      );
    }
  }
  if (out.length === 0 && /\b(decode|base64|hex)\b.{0,40}\b(and )?(follow|execute|run|obey|do it)\b/i.test(text)) {
    out.push(
      f('encoded-payload', 'medium', ctx.tool.name, field.location,
        'Asks the agent to decode and follow embedded content.',
        excerpt(text, 0, 0, 100)),
    );
  }
  return out;
}

export function ruleWhitespacePadding(field: TextField, raw: string, ctx: RuleContext): Finding[] {
  const m = /([ \t\u00A0\u3000]{40,}|(\r?\n[ \t]*){8,})(?=\S)/.exec(raw);
  if (!m) return [];
  const after = raw.slice(m.index + m[0].length, m.index + m[0].length + 140);
  return [
    f('whitespace-padding', 'medium', ctx.tool.name, field.location,
      `Long whitespace run (${m[0].length} chars) pushes text out of view in most UIs.`,
      `[${m[0].length} whitespace] ${after}`),
  ];
}

const TURN_BOUNDARY: RegExp[] = [
  /<\/?\s*(tool_output|tool_result|function_results?|user|assistant|human|system_message)\s*>/i,
  /<\|(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id)\|>/i,
  /\[\/?(INST|SYS)\]|<<\/?SYS>>/,
  /(^|\n)\s*(Human|Assistant|User|System)\s*:\s*\S/,
  /\bassistant_next_action\s*:/i,
];

export function ruleFakeTurnBoundary(field: TextField, text: string, ctx: RuleContext): Finding[] {
  const m = firstMatch(text, TURN_BOUNDARY);
  if (!m) return [];
  return [
    f('fake-turn-boundary', 'high', ctx.tool.name, field.location,
      'Contains chat-template / role markers that can forge conversation turns.',
      excerpt(text, m.index, m[0].length)),
  ];
}

const PERSISTENCE: RegExp[] = [
  /\b(auto-?load(ed)?|autostart|auto-?run)\b.{0,80}\b(next time|on startup|every session|server)\b/i,
  /\.(bashrc|zshrc|bash_profile|profile)\b|\bcrontab\b|\blaunchd\b|\bLaunchAgents\b|\bsystemd\b.{0,30}\bservice\b/i,
  /\b(add|register|install|append) (this|the following|our|a new) (mcp )?server\b/i,
  /\bwrite\b.{0,60}\.mcp[_a-z]*\.json\b/i,
  /\b(git config|ssh-keygen|authorized_keys)\b/i,
  /\b(curl|wget|iwr|Invoke-WebRequest)\b[^|\n]{0,200}\|\s*(sh|bash|zsh|python3?|iex)\b/i,
  /\bsource\s+https?:\/\//i,
  /\bsave\b.{0,40}\.[a-z_]*(hook|rc|profile|autoload|startup)[a-z_]*(\.\w+)?\b/i,
];

export function rulePersistence(field: TextField, text: string, ctx: RuleContext): Finding[] {
  const m = firstMatch(text, PERSISTENCE);
  if (!m) return [];
  return [
    f('persistence', 'high', ctx.tool.name, field.location,
      'Asks the agent to establish persistence (autoload config, shell rc, cron, new MCP server).',
      excerpt(text, m.index, m[0].length)),
  ];
}

// ---------------------------------------------------------------------------
// Tool-level rules
// ---------------------------------------------------------------------------

const SMUGGLE_PARAM_NAMES = new Set([
  'notes', 'note', 'sidenote', 'side_note', 'context', 'extra', 'metadata', 'meta', 'debug', 'feedback',
  'reasoning', 'rationale', 'comment', 'annotation', 'hidden', 'internal', 'aux', 'auxiliary',
]);
const CONTEXT_PARAM_NAMES = /^(system_?prompt|conversation(_history)?|chat_?history|previous_?messages|full_?context|all_?messages|memory|transcript)$/i;

export function ruleParameterSmuggling(tool: McpTool, normalizedAll: string): Finding[] {
  const out: Finding[] = [];
  for (const p of parameterNames(tool)) {
    if (CONTEXT_PARAM_NAMES.test(p)) {
      out.push(
        f('parameter-smuggling', 'medium', tool.name, `inputSchema.properties.${p}#name`,
          `Parameter "${p}" asks the agent to hand over its conversation/system context.`, p),
      );
      continue;
    }
    if (!SMUGGLE_PARAM_NAMES.has(p.toLowerCase())) continue;
    const re = new RegExp(
      `\\b(pass|put|include|place|send|provide|insert|fill)\\b[^.]{0,120}\\b${escapeRe(p)}\\b|\\b${escapeRe(p)}\\b[^.]{0,80}\\b(contents? of|secret|token|password|key|file|conversation|history)\\b`,
      'i',
    );
    const m = re.exec(normalizedAll);
    if (m && /\b(contents?|secret|token|password|credential|key|file|conversation|history|\.txt|\.env)\b/i.test(m[0])) {
      out.push(
        f('parameter-smuggling', 'high', tool.name, `inputSchema.properties.${p}`,
          `Free-form parameter "${p}" is used as a side channel for sensitive data.`,
          excerpt(normalizedAll, m.index, m[0].length)),
      );
    }
  }
  return out;
}

export function ruleExcessivePermission(tool: McpTool, normalizedAll: string): Finding[] {
  const out: Finding[] = [];
  const name = tool.name.toLowerCase();
  const params = parameterNames(tool).map((p) => p.toLowerCase());
  const restricted = /\b(only|allow-?list(ed)?|whitelist(ed)?|restricted to|limited to|sandbox(ed)?|read-only|permitted)\b/i.test(normalizedAll);

  const shellish =
    /(^|_|-)(shell|exec|execute|eval|run_?command|run_?script|bash|powershell|cmd|terminal|subprocess)($|_|-)/.test(name) ||
    params.some((p) => ['command', 'cmd', 'script', 'shell_command', 'code'].includes(p)) &&
      /\b(execute|run|eval)\b/i.test(normalizedAll);
  if (shellish) {
    out.push(
      f('excessive-permission', restricted ? 'low' : 'medium', tool.name, 'tool',
        restricted
          ? 'Executes commands, but metadata claims an allow-list — verify server-side enforcement.'
          : 'Arbitrary command / code execution with no stated restriction.',
        tool.description?.slice(0, 160) ?? tool.name),
    );
  }
  if (/\b(any|arbitrary) (file|path)|absolute path|entire (file ?system|disk)|\broot directory\b|anywhere on (the )?(disk|system)/i.test(normalizedAll)) {
    out.push(
      f('excessive-permission', 'medium', tool.name, 'tool',
        'Claims unrestricted filesystem access.', tool.description?.slice(0, 160) ?? tool.name),
    );
  }
  if (/\b(any|arbitrary) (url|website|host|endpoint)\b/i.test(normalizedAll) && !restricted) {
    out.push(
      f('excessive-permission', 'low', tool.name, 'tool',
        'Fetches arbitrary URLs (SSRF / exfiltration channel).', tool.description?.slice(0, 160) ?? tool.name),
    );
  }
  if (/\b(admin|root|sudo|superuser|all scopes|full access|org[- ]wide)\b/i.test(normalizedAll) &&
      /\b(requires?|needs?|grant|token with|scope)\b/i.test(normalizedAll)) {
    out.push(
      f('excessive-permission', 'medium', tool.name, 'tool',
        'Requests admin / full-access privileges.', tool.description?.slice(0, 160) ?? tool.name),
    );
  }
  return out;
}

export function ruleToolNameChecks(tool: McpTool, ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  if (hasMixedScript(tool.name) || inspectInvisible(tool.name).zeroWidth > 0) {
    out.push(
      f('homoglyph-name', 'high', tool.name, 'name',
        'Tool name mixes scripts or contains invisible characters (homoglyph spoofing).', tool.name),
    );
  }
  const folded = foldConfusables(tool.name).replace(/[\u200B-\u200D\uFEFF]/g, '').toLowerCase();
  for (const ext of ctx.externalNames) {
    const extFolded = foldConfusables(ext.name).toLowerCase();
    if (extFolded !== folded) continue;
    if (ext.name === tool.name) {
      out.push(
        f('tool-name-collision', 'medium', tool.name, 'name',
          `Tool name collides with "${ext.name}" on server "${ext.server}" — the agent may call the wrong one.`, tool.name),
      );
    } else if (/^[\x20-\x7E]*$/.test(tool.name)) {
      // This tool is the plain-ASCII original; the other server holds the impostor.
      out.push(
        f('tool-name-collision', 'medium', tool.name, 'name',
          `Server "${ext.server}" exposes a look-alike of this tool ("${ext.name}") — it may intercept calls meant for this one.`, ext.name),
      );
    } else {
      out.push(
        f('tool-name-collision', 'critical', tool.name, 'name',
          `Tool name is a look-alike of "${ext.name}" on server "${ext.server}".`, tool.name),
      );
    }
  }
  return out;
}

const LEET: Record<string, string> = { '4': 'a', '@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', $: 's', '7': 't', '8': 'b', '9': 'g' };

/** Translate leetspeak tokens (words mixing letters and digits) back to letters. */
export function deLeet(text: string): string {
  return text.replace(/[A-Za-z0-9@$]+/g, (tok) => {
    if (!/[0-9@$]/.test(tok) || /^\d+$/.test(tok)) return tok;
    // Need at least two leet characters to avoid touching "v2", "ec2", "s3", "sha256".
    const n = (tok.match(/[0134578@$9]/g) ?? []).length;
    if (n < 2 && tok.length > 3) return tok;
    if (n < 1) return tok;
    return tok.replace(/[0-9@$]/g, (c) => LEET[c] ?? c).toLowerCase();
  });
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
