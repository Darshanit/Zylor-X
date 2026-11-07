import { describe, it, expect } from "vitest";
import { parseEnvelope, parseStrictJson, StrictParseError } from "../src/parse/index.js";
import { kit } from "./helpers.js";
const code = (f: () => unknown) => { try { f(); return "NO_ERROR"; } catch (e) { return e instanceof StrictParseError ? e.code : "OTHER:" + e; } };
describe("strict JSON parsing", () => {
  it("round-trips a valid envelope", () => { const x = kit(); const e = parseEnvelope(JSON.stringify(x.envelope)); expect(e.payload.metadata.changeId).toBe("CHG-1"); });
  it("rejects duplicate keys (JSON.parse would keep the last one)", () => expect(code(() => parseStrictJson('{"a":1,"a":2}'))).toBe("DUPLICATE_KEY"));
  it("rejects duplicate keys in nested objects", () => expect(code(() => parseStrictJson('{"a":{"b":1,"b":2}}'))).toBe("DUPLICATE_KEY"));
  it("duplicate key smuggling in a real envelope is caught", () => {
    const json = JSON.stringify(kit().envelope).replace('"changeId":"CHG-1"', '"changeId":"CHG-1","changeId":"CHG-EVIL"');
    expect(code(() => parseEnvelope(json))).toBe("DUPLICATE_KEY"); });
  it("rejects __proto__ keys", () => expect(code(() => parseStrictJson('{"__proto__":{"x":1}}'))).toBe("FORBIDDEN_KEY"));
  it("rejects decimals and exponents", () => { expect(code(() => parseStrictJson('{"a":1.5}'))).toBe("NUMBER_NOT_INTEGER"); expect(code(() => parseStrictJson('{"a":1e3}'))).toBe("NUMBER_NOT_INTEGER"); });
  it("rejects unsafe integers and negative zero", () => { expect(code(() => parseStrictJson('{"a":9007199254740993}'))).toBe("NUMBER_UNSAFE"); expect(code(() => parseStrictJson('{"a":-0}'))).toBe("NUMBER_UNSAFE"); });
  it("accepts safe integers", () => expect(parseStrictJson('{"a":9007199254740991}')).toEqual({ a: 9007199254740991 }));
  it("rejects lone surrogates", () => expect(code(() => parseStrictJson('{"a":"\\ud800"}'))).toBe("LONE_SURROGATE"));
  it("accepts valid surrogate pairs", () => expect(parseStrictJson('{"a":"\\ud83d\\ude00"}')).toEqual({ a: "\u{1F600}" }));
  it("rejects trailing data and syntax errors", () => { expect(code(() => parseStrictJson('{"a":1} x'))).toBe("TRAILING"); expect(code(() => parseStrictJson('{"a":1,}'))).toBe("SYNTAX"); expect(code(() => parseStrictJson("{'a':1}"))).toBe("SYNTAX"); });
  it("rejects excessive nesting", () => expect(code(() => parseStrictJson("[".repeat(100) + "]".repeat(100)))).toBe("TOO_DEEP"));
  it("rejects missing required fields (shape)", () => { const e: any = JSON.parse(JSON.stringify(kit().envelope)); delete e.payload.actor.owner; expect(code(() => parseEnvelope(JSON.stringify(e)))).toBe("SHAPE"); });
  it("rejects wrong field types (shape)", () => { const e: any = JSON.parse(JSON.stringify(kit().envelope)); e.payload.constraints.allowIamEffects = "no"; expect(code(() => parseEnvelope(JSON.stringify(e)))).toBe("SHAPE"); });
});
