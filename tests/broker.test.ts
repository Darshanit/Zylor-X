import { describe, it, expect } from "vitest";
import { Broker, InMemoryNonceStore } from "../src/broker/index.js";
import { kit, NOW, PRESENTED } from "./helpers.js";
function mk(x: ReturnType<typeof kit>, throwOnIssue = false) {
  let issued = 0; const store = new InMemoryNonceStore();
  const b = new Broker({ ...x.resolver, nonceStore: store, revokedIssuerKeyIds: new Set(), knownApprovers: new Set(["approver@test"]),
    credentialIssuer: { issue: () => { if (throwOnIssue) throw new Error("sts down"); issued++;
      return { credentialId: "C", sourceIdentity: "CHG-1", issuedAt: "", expiresAt: "", permissions: [] }; } } });
  return { b, store, count: () => issued };
}
describe("broker fail-closed behaviour", () => {
  it("issues once, then rejects replay", () => { const x = kit(), m = mk(x);
    expect(m.b.issue(x.envelope, NOW, PRESENTED).credentialId).toBe("C"); expect(() => m.b.issue(x.envelope, NOW, PRESENTED)).toThrow("NONCE_REPLAY"); expect(m.count()).toBe(1); });
  it("issues nothing when verification fails", () => { const x = kit(); x.envelope.payload.effects[0]!.resourceId = "t"; const m = mk(x);
    expect(() => m.b.issue(x.envelope, NOW, PRESENTED)).toThrow("BROKER_DENIED"); expect(m.count()).toBe(0); });
  it("does not consume the nonce when verification fails", () => { const x = kit(), m = mk(x);
    expect(() => m.b.issue(x.envelope, NOW, { ...PRESENTED, planHash: "WRONG" })).toThrow("PLAN_MISMATCH"); expect(m.store.consumeOnce("N-1")).toBe(true); });
  it("refuses when plan hash or target is omitted", () => { const x = kit(), m = mk(x);
    expect(() => m.b.issue(x.envelope, NOW, { ...PRESENTED, planHash: undefined })).toThrow("PLAN_MISSING");
    expect(() => m.b.issue(x.envelope, NOW, { ...PRESENTED, target: undefined })).toThrow("TARGET_MISSING"); expect(m.count()).toBe(0); });
  it("burns the nonce even if credential issuance then fails", () => { const x = kit(), m = mk(x, true);
    expect(() => m.b.issue(x.envelope, NOW, PRESENTED)).toThrow("sts down"); expect(m.store.consumeOnce("N-1")).toBe(false); });
  it("denies (not crashes) on a structurally broken envelope", () => { const x = kit(), m = mk(x); (x.envelope as any).payload.issuer = undefined;
    expect(() => m.b.issue(x.envelope, NOW, PRESENTED)).toThrow("BROKER_DENIED"); expect(m.count()).toBe(0); });
});
