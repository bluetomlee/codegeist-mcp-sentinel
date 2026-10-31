/**
 * Regression suite over the odin-harness-derived payload corpus.
 * Every malicious sample must yield at least one finding of severity >= medium;
 * every benign control must yield nothing at severity >= low.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { atLeast, scanTool } from '../src/scanner';

interface Sample { id: string; technique: string; text: string }
const corpus = JSON.parse(readFileSync(join(__dirname, '../fixtures/odin-corpus.json'), 'utf8')) as {
  malicious: Sample[];
  benign: Sample[];
};
const ctx = {
  siblingNames: [],
  externalNames: ['search_docs', 'read_file', 'write_file', 'http_get', 'run_shell', 'read_email'].map((name) => ({ server: 'builtin', name })),
};

describe('odin corpus — malicious samples are detected', () => {
  it.each(corpus.malicious.map((s) => [s.id, s] as const))('%s', (_id, s) => {
    const findings = atLeast(scanTool({ name: 'poisoned_tool', description: s.text }, ctx), 'medium');
    expect(findings.length, `${s.technique}`).toBeGreaterThan(0);
  });
});

describe('odin corpus — benign controls are clean', () => {
  it.each(corpus.benign.map((s) => [s.id, s] as const))('%s', (_id, s) => {
    expect(atLeast(scanTool({ name: 'kb_tool', description: s.text }, ctx), 'low')).toEqual([]);
  });
});

it('detection rate summary', () => {
  const detected = corpus.malicious.filter((s) => atLeast(scanTool({ name: 'p', description: s.text }, ctx), 'medium').length > 0);
  expect(detected.length / corpus.malicious.length).toBe(1);
});
