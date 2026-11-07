/**
 * Strict JSON parser for untrusted contract envelopes (RFC 8785 assumes I-JSON input).
 * Rejects: duplicate keys, "__proto__", lone surrogates, non-integer or unsafe numbers, -0,
 * trailing data, and excessive nesting. JSON.parse silently accepts all of these.
 */
export class StrictParseError extends Error {
  constructor(public code: string, message: string) { super(`${code}: ${message}`); }
}
const MAX_DEPTH = 32, MAX_BYTES = 1_000_000;
const STR = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
const NUM = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

export function parseStrictJson(text: string): unknown {
  if (Buffer.byteLength(text, "utf8") > MAX_BYTES) throw new StrictParseError("TOO_LARGE", "input too large");
  let i = 0;
  const err = (code: string, m: string): never => { throw new StrictParseError(code, `${m} (offset ${i})`); };
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i]!)) i++; };
  const lit = (word: string, val: unknown) => { if (!text.startsWith(word, i)) err("SYNTAX", "bad literal"); i += word.length; return val; };
  function str(): string {
    STR.lastIndex = i; const m = STR.exec(text);
    if (!m) return err("SYNTAX", "bad string");
    i += m[0].length; const s = JSON.parse(m[0]) as string;
    if (LONE.test(s)) err("LONE_SURROGATE", "unpaired surrogate in string");
    return s;
  }
  function num(): number {
    NUM.lastIndex = i; const m = NUM.exec(text);
    if (!m) return err("SYNTAX", "bad number");
    const tok = m[0]; i += tok.length;
    if (/[.eE]/.test(tok)) err("NUMBER_NOT_INTEGER", "carry decimals/exponents as strings");
    const n = Number(tok);
    if (!Number.isSafeInteger(n) || Object.is(n, -0)) err("NUMBER_UNSAFE", "carry large integers as strings");
    return n;
  }
  function value(d: number): unknown {
    if (d > MAX_DEPTH) err("TOO_DEEP", "nesting too deep");
    ws(); const c = text[i];
    if (c === "{") return obj(d);
    if (c === "[") return arr(d);
    if (c === '"') return str();
    if (c === "t") return lit("true", true);
    if (c === "f") return lit("false", false);
    if (c === "n") return lit("null", null);
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return num();
    return err("SYNTAX", "unexpected token");
  }
  function obj(d: number): Record<string, unknown> {
    i++; const o: Record<string, unknown> = {}, seen = new Set<string>(); ws();
    if (text[i] === "}") { i++; return o; }
    for (;;) {
      ws(); if (text[i] !== '"') err("SYNTAX", "expected key");
      const k = str();
      if (k === "__proto__") err("FORBIDDEN_KEY", "__proto__");
      if (seen.has(k)) err("DUPLICATE_KEY", JSON.stringify(k));
      seen.add(k); ws();
      if (text[i] !== ":") err("SYNTAX", "expected ':'");
      i++; o[k] = value(d + 1); ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "}") { i++; return o; }
      err("SYNTAX", "expected ',' or '}'");
    }
  }
  function arr(d: number): unknown[] {
    i++; const a: unknown[] = []; ws();
    if (text[i] === "]") { i++; return a; }
    for (;;) {
      a.push(value(d + 1)); ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "]") { i++; return a; }
      err("SYNTAX", "expected ',' or ']'");
    }
  }
  const v = value(0); ws();
  if (i !== text.length) err("TRAILING", "trailing data");
  return v;
}
