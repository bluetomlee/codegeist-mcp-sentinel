/**
 * Unicode helpers: detect and neutralise invisible / deceptive characters.
 */

/** Zero-width and other format characters commonly used to split keywords or hide text. */
const ZERO_WIDTH = /[\u200B\u200C\u200D\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD\u180E\u034F]/gu;

/** Unicode "tag" block (U+E0000–U+E007F): invisible ASCII smuggling. */
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;

/** Bidirectional control characters (Trojan Source style). */
const BIDI = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/gu;

/** Private-use and variation-selector ranges that render invisibly. */
const VARIATION_SELECTORS = /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;

export interface InvisibleReport {
  zeroWidth: number;
  tags: number;
  bidi: number;
  variationSelectors: number;
  /** ASCII text decoded from Unicode tag characters, if any. */
  decodedTags: string;
}

export function inspectInvisible(text: string): InvisibleReport {
  const tags = text.match(TAG_CHARS) ?? [];
  const decodedTags = tags
    .map((ch) => {
      const cp = ch.codePointAt(0)! - 0xe0000;
      return cp >= 0x20 && cp < 0x7f ? String.fromCharCode(cp) : '';
    })
    .join('');
  return {
    zeroWidth: (text.match(ZERO_WIDTH) ?? []).length,
    tags: tags.length,
    bidi: (text.match(BIDI) ?? []).length,
    variationSelectors: (text.match(VARIATION_SELECTORS) ?? []).length,
    decodedTags,
  };
}

/**
 * Produce the text a model would effectively "read": invisible characters removed,
 * tag-smuggled ASCII decoded and appended, NFKC applied (folds full-width letters etc.),
 * and whitespace runs collapsed.
 */
export function normalizeForAnalysis(text: string): string {
  const { decodedTags } = inspectInvisible(text);
  let out = text
    .replace(TAG_CHARS, '')
    .replace(ZERO_WIDTH, '')
    .replace(BIDI, '')
    .replace(VARIATION_SELECTORS, '');
  out = out.normalize('NFKC');
  if (decodedTags) out += '\n' + decodedTags;
  return out.replace(/[ \t\u00A0\u3000]+/g, ' ');
}

/** Render invisible characters visibly for evidence strings. */
export function makeVisible(text: string): string {
  return text
    .replace(TAG_CHARS, (ch) => `<U+${ch.codePointAt(0)!.toString(16).toUpperCase()}>`)
    .replace(ZERO_WIDTH, (ch) => `<U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}>`)
    .replace(BIDI, (ch) => `<U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}>`);
}

/** Map of common Cyrillic/Greek confusables to their Latin look-alikes. */
const CONFUSABLES: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', һ: 'h', ԁ: 'd', ԛ: 'q', ԝ: 'w',
  А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', Х: 'X',
  α: 'a', ο: 'o', ρ: 'p', ν: 'v', ι: 'i', κ: 'k', τ: 't', υ: 'u',
};

/** Fold confusable characters to Latin so `ѕearch_docs` compares equal to `search_docs`. */
export function foldConfusables(text: string): string {
  let out = '';
  for (const ch of text.normalize('NFKC')) out += CONFUSABLES[ch] ?? ch;
  return out;
}

/** True when an identifier mixes Latin with non-Latin letters (classic homoglyph spoof). */
export function hasMixedScript(identifier: string): boolean {
  const hasLatin = /[A-Za-z]/.test(identifier);
  const hasNonLatinLetter = /[^\x00-\x7F]/u.test(identifier) && /\p{L}/u.test(identifier.replace(/[\x00-\x7F]/g, ''));
  return hasLatin && hasNonLatinLetter;
}
