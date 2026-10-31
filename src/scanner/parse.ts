import type { McpTool } from './types';

export const MAX_INPUT_BYTES = 512 * 1024;
export const MAX_TOOLS = 500;

export class ParseError extends Error {}

/**
 * Accepts the shapes people actually paste:
 *  - a JSON-RPC `tools/list` response: { "result": { "tools": [...] } }
 *  - a bare result object: { "tools": [...] }
 *  - an array of tools: [...]
 *  - a single tool: { "name": ..., "description": ... }
 * Also accepts `input_schema` / `parameters` (Anthropic / OpenAI style) as aliases for `inputSchema`.
 */
export function parseToolList(input: string | unknown): McpTool[] {
  let data: unknown = input;
  if (typeof input === 'string') {
    if (Buffer.byteLength(input, 'utf8') > MAX_INPUT_BYTES) {
      throw new ParseError(`Input too large (max ${MAX_INPUT_BYTES} bytes).`);
    }
    try {
      data = JSON.parse(input);
    } catch (e) {
      throw new ParseError(`Input is not valid JSON: ${(e as Error).message}`);
    }
  }
  let list: unknown;
  if (Array.isArray(data)) list = data;
  else if (isObj(data) && isObj(data.result) && Array.isArray(data.result.tools)) list = data.result.tools;
  else if (isObj(data) && Array.isArray(data.tools)) list = data.tools;
  else if (isObj(data) && typeof data.name === 'string') list = [data];
  else throw new ParseError('Could not find a tool list. Paste the JSON from an MCP tools/list response.');

  const arr = list as unknown[];
  if (arr.length > MAX_TOOLS) throw new ParseError(`Too many tools (max ${MAX_TOOLS}).`);
  return arr.filter(isObj).filter((t) => typeof t.name === 'string').map((t) => {
    const schema = t.inputSchema ?? t.input_schema ?? t.parameters;
    return {
      name: String(t.name),
      title: typeof t.title === 'string' ? t.title : undefined,
      description: typeof t.description === 'string' ? t.description : undefined,
      inputSchema: isObj(schema) ? (schema as McpTool['inputSchema']) : undefined,
      annotations: isObj(t.annotations) ? t.annotations : undefined,
    };
  });
}

function isObj(v: unknown): v is Record<string, any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
