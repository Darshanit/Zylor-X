import type { KeyObject } from "node:crypto";
import { APPROVAL_CONTEXT, ISSUANCE_CONTEXT, type ContractEnvelope, type VerificationCode,
  type VerificationContext, type VerificationResult } from "../contract/types.js";
import { assertSupportedAlgorithm, hashPayload, verifySignature } from "../signing/index.js";

export interface KeyResolver {
  getIssuerPublicKey(keyId: string): KeyObject | undefined;
  /** MUST return a key only if keyId is registered to exactly this principal. */
  getApproverPublicKey(principal: string, keyId: string): KeyObject | undefined;
}
const CLOCK_SKEW_MS = 60_000;

export function verifyContract(e: ContractEnvelope, c: VerificationContext, k: KeyResolver): VerificationResult {
  let h: string;
  try { assertSupportedAlgorithm(e.payload); h = hashPayload(e.payload); }
  catch (err) { return { ok: false, code: "ALGORITHM_MISMATCH", reason: String(err) }; }
  const fail = (code: VerificationCode, reason?: string): VerificationResult =>
    ({ ok: false, code, contractHash: h, ...(reason ? { reason } : {}) });
  const p = e.payload, { approval, issuer } = e.signatures, pr = c.presented;

  if (e.signatures.contractHash !== h || approval.signature.signedHash !== h || issuer.signature.signedHash !== h)
    return fail("HASH_MISMATCH");

  if (issuer.keyId !== p.issuer.keyId) return fail("ISSUER_KEY_MISMATCH");
  if (c.revokedIssuerKeyIds.has(p.issuer.keyId)) return fail("REVOKED_ISSUER");

  if (p.sponsor.approval.type !== "human") return fail("UNSUPPORTED_APPROVAL_TYPE"); // templates: not in spike
  const a = approval.signer;
  if (!c.knownApprovers.has(a) || a !== p.sponsor.approval.requiredApprover) return fail("UNKNOWN_APPROVER");
  if (a === p.sponsor.principal || a === p.actor.owner) return fail("SEPARATION_OF_DUTIES");

  const ak = k.getApproverPublicKey(a, approval.keyId), ik = k.getIssuerPublicKey(issuer.keyId);
  if (!ak || !verifySignature(approval.signature, ak, APPROVAL_CONTEXT, h)) return fail("BAD_APPROVAL_SIGNATURE");
  if (!ik || !verifySignature(issuer.signature, ik, ISSUANCE_CONTEXT, h)) return fail("BAD_ISSUER_SIGNATURE");

  if (!p.metadata.nonce) return fail("NONCE_MISSING");
  const created = Date.parse(p.metadata.createdAt), expires = Date.parse(p.metadata.expiresAt), now = c.now.getTime();
  if (!Number.isFinite(created) || !Number.isFinite(expires) || expires <= created) return fail("INVALID_TIMESTAMP");
  if (now + CLOCK_SKEW_MS < created) return fail("NOT_YET_VALID");
  if (now >= expires) return fail("EXPIRED");
  if (p.authorization.sourceIdentity !== p.metadata.changeId) return fail("SOURCE_IDENTITY_MISMATCH");

  // Target binding: the account/region being issued into must be presented and must match. Fail closed.
  if (!pr.target) return fail("TARGET_MISSING");
  if (pr.target.account !== p.target.account || pr.target.region !== p.target.region) return fail("TARGET_MISMATCH");
  if (p.constraints.allowedRegions && !p.constraints.allowedRegions.includes(p.target.region)) return fail("REGION_NOT_ALLOWED");

  const t = p.source.terraform;
  if (t) {
    if (pr.planHash === undefined) return fail("PLAN_MISSING");
    if (pr.planHash !== t.planHash) return fail("PLAN_MISMATCH");
    if (!pr.state) return fail("STATE_MISSING");
    if (pr.state.lineage !== t.state.lineage || pr.state.serial !== t.state.serial) return fail("STATE_MISMATCH");
  }
  return { ok: true, code: "OK", contractHash: h };
}
