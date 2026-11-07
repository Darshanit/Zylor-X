import { describe, it, expect } from "vitest";
import { classifyDeniedA01 } from "../src/scenarios/a01.js";
import { kit } from "./helpers.js";
const req = { action: "iam:CreateRole", resourceType: "aws.iam.role", resourceId: "evil" };
describe("A01 / A44 classification", () => {
  it("ATTEMPTED-DENIED only with matching SourceIdentity and out-of-contract action", () => { const x = kit();
    expect(classifyDeniedA01(x.envelope, { ...req, sourceIdentity: "CHG-1" })).toBe("ATTEMPTED-DENIED"); });
  it("no SourceIdentity -> UNRELATED-DENIAL", () => expect(classifyDeniedA01(kit().envelope, req)).toBe("UNRELATED-DENIAL"));
  it("different change id -> UNRELATED-DENIAL", () => expect(classifyDeniedA01(kit().envelope, { ...req, sourceIdentity: "CHG-9" })).toBe("UNRELATED-DENIAL"));
  it("in-contract denial -> BUG-DENIED-IN-CONTRACT", () => { const x = kit();
    x.envelope.payload.effects.push({ effectId: "E2", operation: "iam:CreateRole", resourceType: "aws.iam.role", resourceId: "evil" });
    expect(classifyDeniedA01(x.envelope, { ...req, sourceIdentity: "CHG-1" })).toBe("BUG-DENIED-IN-CONTRACT"); });
});
