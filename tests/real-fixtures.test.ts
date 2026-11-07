import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { normalizeEvent } from "../src/catalog/index.js";
const dir = join(__dirname, "fixtures", "real");
const files = readdirSync(dir).filter(f => f.endsWith(".json"));
describe.skipIf(files.length === 0)("real CloudTrail fixtures (from your sandbox)", () => {
  it.each(files)("%s normalizes without error", f => {
    const o = normalizeEvent(JSON.parse(readFileSync(join(dir, f), "utf8")));
    expect(o.error).toBeUndefined();
    if (f.startsWith("denied-")) expect(o.outcome).toBe("DENIED");
    if (f.startsWith("allowed-")) expect(o.outcome).toBe("SUCCEEDED");
    console.log(f, JSON.stringify({ outcome: o.outcome, mapped: o.mapped, apiAction: o.apiAction, sourceIdentity: o.sourceIdentity ?? "ABSENT", region: o.region }));
  });
  it("records whether SourceIdentity survives on denied events (the A44 question)", () => {
    for (const f of files.filter(x => x.startsWith("denied-"))) {
      const o = normalizeEvent(JSON.parse(readFileSync(join(dir, f), "utf8")));
      expect(o.sourceIdentity, `${f}: SourceIdentity absent on denied event, redesign correlation`).toBeDefined();
    }
  });
});
