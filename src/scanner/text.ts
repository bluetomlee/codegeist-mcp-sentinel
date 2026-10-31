import type { JsonSchema, McpTool } from './types';

/** A piece of text pulled out of a tool definition, plus where it came from. */
export interface TextField {
  location: string;
  raw: string;
}

/** Collect every model-visible string in a tool definition. */
export function extractTextFields(tool: McpTool): TextField[] {
  const fields: TextField[] = [];
  if (tool.title) fields.push({ location: 'title', raw: tool.title });
  if (tool.description) fields.push({ location: 'description', raw: tool.description });
  if (tool.inputSchema) walkSchema(tool.inputSchema, 'inputSchema', fields, 0);
  return fields;
}

function walkSchema(schema: JsonSchema, path: string, out: TextField[], depth: number): void {
  if (!schema || typeof schema !== 'object' || depth > 8) return;
  if (typeof schema.description === 'string') out.push({ location: `${path}.description`, raw: schema.description });
  if (typeof schema.title === 'string') out.push({ location: `${path}.title`, raw: schema.title });
  if (typeof schema.default === 'string') out.push({ location: `${path}.default`, raw: schema.default });
  if (Array.isArray(schema.enum)) {
    schema.enum.forEach((v, i) => {
      if (typeof v === 'string') out.push({ location: `${path}.enum[${i}]`, raw: v });
    });
  }
  if (schema.properties && typeof schema.properties === 'object') {
    for (const [name, sub] of Object.entries(schema.properties)) {
      // Property names are model-visible too and can hide text.
      out.push({ location: `${path}.properties.${name}#name`, raw: name });
      walkSchema(sub, `${path}.properties.${name}`, out, depth + 1);
    }
  }
  if (schema.items) {
    const items = Array.isArray(schema.items) ? schema.items : [schema.items];
    items.forEach((it, i) => walkSchema(it, `${path}.items[${i}]`, out, depth + 1));
  }
}

/** List input parameter names (top level) for a tool. */
export function parameterNames(tool: McpTool): string[] {
  return Object.keys(tool.inputSchema?.properties ?? {});
}

/** Truncated excerpt around a match index. */
export function excerpt(text: string, index: number, length: number, radius = 60): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  let s = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) s = '…' + s;
  if (end < text.length) s = s + '…';
  return s.length > 200 ? s.slice(0, 199) + '…' : s;
}

/** Deterministic JSON with sorted keys, used for hashing. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const obj = value as Record<string, unknown>;
  return (
    '{' +
    Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k]))
      .join(',') +
    '}'
  );
}
