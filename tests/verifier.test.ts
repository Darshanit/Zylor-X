import { describe, it, expect } from "vitest";
import { createKeyPair, signApproval, signIssuer, buildEnvelope, hashPayload } from "../src/signing/index.js";
import { verifyContract } from "../src/verifier/index.js";
import { kit, ctx, makePayload, PRESENTED } from "./helpers.js";

describe("verifier: happy path and integrity", () => {
  it("valid contract verifies", () => { const x = kit(); expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("OK"); });
  it("hash is prefixed sha256: and independent of key order", () => {
    const p = makePayload(), r: any = {}; for (const k of Object.keys(p).reverse()) r[k] = (p as any)[k];
    expect(hashPayload(p)).toMatch(/^sha256:[0-9a-f]{64}$/); expect(hashPayload(r)).toBe(hashPayload(p)); });
  it("optional field undefined hashes the same as absent", () => {
    const p = makePayload(), q = makePayload(); (q.source as any).workflow = undefined; expect(hashPayload(q)).toBe(hashPayload(p)); });
  it("tampered payload rejected", () => { const x = kit(); x.envelope.payload.effects[0]!.resourceId = "evil"; expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("HASH_MISMATCH"); });
  it("approval signature cannot serve as issuer signature (domain separation)", () => {
    const x = kit(); x.envelope.signatures.issuer = { keyId: "issuer-1", signature: { ...x.envelope.signatures.approval.signature } };
    expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("BAD_ISSUER_SIGNATURE"); });
  it("unsupported algorithm rejected", () => { const x = kit(); (x.envelope.payload.evidence as any).signingAlgorithm = "RSA"; expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("ALGORITHM_MISMATCH"); });
});
describe("verifier: keys and approvers", () => {
  it("revoked issuer rejected", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ revokedIssuerKeyIds: new Set(["issuer-1"]) }), x.resolver).code).toBe("REVOKED_ISSUER"); });
  it("envelope issuer key must equal payload issuer.keyId", () => { const x = kit(); x.envelope.signatures.issuer.keyId = "issuer-OTHER"; expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("ISSUER_KEY_MISMATCH"); });
  it("approver key must belong to the claimed principal", () => {
    const x = kit(); const other = createKeyPair();
    x.envelope.signatures.approval = signApproval(x.payload, other.privateKey, "other-key", "approver@test");
    const resolver = { ...x.resolver, getApproverPublicKey: (p: string, k: string) => (k === "other-key" && p === "other@test" ? other.publicKey : x.resolver.getApproverPublicKey(p, k)) };
    expect(verifyContract(x.envelope, ctx(), resolver).code).toBe("BAD_APPROVAL_SIGNATURE"); });
  it("approver must be the required approver", () => {
    const x = kit(); x.envelope.signatures.approval.signer = "other@test"; expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("UNKNOWN_APPROVER"); });
  it("separation of duties: approver equals sponsor", () => {
    const x = kit(p => { p.sponsor.approval.requiredApprover = "sponsor@test"; });
    x.envelope.signatures.approval.signer = "sponsor@test"; expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("SEPARATION_OF_DUTIES"); });
  it("separation of duties: approver equals actor.owner", () => {
    const x = kit(p => { p.actor.owner = "approver@test"; }); expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("SEPARATION_OF_DUTIES"); });
  it("standing-template approval is unsupported in the spike (fails closed)", () => {
    const x = kit(p => { p.sponsor.approval.type = "standing-template"; }); expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("UNSUPPORTED_APPROVAL_TYPE"); });
});
describe("verifier: time", () => {
  it("expired", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ now: new Date("2026-10-01T00:00:00Z") }), x.resolver).code).toBe("EXPIRED"); });
  it("not yet valid", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ now: new Date("2026-09-29T00:00:00Z") }), x.resolver).code).toBe("NOT_YET_VALID"); });
  it("malformed expiresAt is not 'never expires'", () => { const x = kit(p => { p.metadata.expiresAt = "not-a-date"; }); expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("INVALID_TIMESTAMP"); });
  it("expiresAt before createdAt rejected", () => { const x = kit(p => { p.metadata.expiresAt = "2026-09-29T00:00:00Z"; }); expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("INVALID_TIMESTAMP"); });
});
describe("verifier: terraform binding (fail closed)", () => {
  it("plan mismatch", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ presented: { ...PRESENTED, planHash: "X" } }), x.resolver).code).toBe("PLAN_MISMATCH"); });
  it("plan omitted", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ presented: { ...PRESENTED, planHash: undefined } }), x.resolver).code).toBe("PLAN_MISSING"); });
  it("state serial mismatch", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ presented: { ...PRESENTED, state: { lineage: "L-1", serial: "8" } } }), x.resolver).code).toBe("STATE_MISMATCH"); });
  it("state lineage mismatch", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ presented: { ...PRESENTED, state: { lineage: "L-2", serial: "7" } } }), x.resolver).code).toBe("STATE_MISMATCH"); });
  it("state omitted", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ presented: { ...PRESENTED, state: undefined } }), x.resolver).code).toBe("STATE_MISSING"); });
  it("contract without terraform binding does not require plan/state", () => {
    const x = kit(p => { delete p.source.terraform; }); expect(verifyContract(x.envelope, ctx({ presented: { target: PRESENTED.target } }), x.resolver).code).toBe("OK"); });
});
describe("verifier: target binding (A28)", () => {
  it("target omitted", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ presented: { ...PRESENTED, target: undefined } }), x.resolver).code).toBe("TARGET_MISSING"); });
  it("wrong account", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ presented: { ...PRESENTED, target: { account: "222222222222", region: "ap-south-1" } } }), x.resolver).code).toBe("TARGET_MISMATCH"); });
  it("wrong region", () => { const x = kit(); expect(verifyContract(x.envelope, ctx({ presented: { ...PRESENTED, target: { account: "111111111111", region: "us-east-1" } } }), x.resolver).code).toBe("TARGET_MISMATCH"); });
  it("contract target outside its own allowedRegions rejected", () => { const x = kit(p => { p.constraints.allowedRegions = ["eu-west-1"]; }); expect(verifyContract(x.envelope, ctx(), x.resolver).code).toBe("REGION_NOT_ALLOWED"); });
});
