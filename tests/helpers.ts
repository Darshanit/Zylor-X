import { createKeyPair, signApproval, signIssuer, buildEnvelope } from "../src/signing/index.js";
import type { ContractPayload, Presented, VerificationContext } from "../src/contract/types.js";
import type { KeyResolver } from "../src/verifier/index.js";

export const NOW = new Date("2026-09-30T12:00:00Z");
export const PRESENTED: Presented = { planHash: "PLAN-1", state: { lineage: "L-1", serial: "7" },
  target: { account: "111111111111", region: "ap-south-1" } };

export function makePayload(): ContractPayload {
  return {
    apiVersion: "example.invalid/v0.2",
    metadata: { contractId: "EC-1", changeId: "CHG-1", createdAt: "2026-09-30T00:00:00Z", expiresAt: "2026-09-30T23:59:59Z", nonce: "N-1" },
    issuer: { id: "control-plane/sandbox", keyId: "issuer-1" },
    sponsor: { principal: "sponsor@test", approval: { type: "human", requiredApprover: "approver@test" } },
    actor: { type: "ci", identity: "github-actions/repo", owner: "owner@test" },
    source: { repository: "repo", commit: "abc",
      terraform: { planHash: "PLAN-1", savedPlanArtifact: "s3://plans/1", state: { lineage: "L-1", serial: "7" } } },
    target: { environment: "sandbox", cloud: "aws", account: "111111111111", region: "ap-south-1" },
    effects: [{ effectId: "E1", operation: "s3:PutObject", resourceType: "aws.s3.object", resourceId: "bucket/x" }],
    constraints: { maxResourcesAffected: 5, allowIamEffects: false, allowRbacEffects: false,
      allowDestructiveEffects: false, allowedRegions: ["ap-south-1"] },
    forbiddenOperations: ["iam:CreateRole", "iam:AttachRolePolicy"],
    recovery: { classification: "reversible" },
    authorization: { mode: "brokered", sourceIdentity: "CHG-1" },
    evidence: { signingAlgorithm: "Ed25519", hashAlgorithm: "SHA-256" },
  };
}
export function kit(edit?: (p: ContractPayload) => void) {
  const payload = makePayload(); edit?.(payload);
  const issuer = createKeyPair(), approver = createKeyPair();
  const envelope = buildEnvelope(payload,
    signApproval(payload, approver.privateKey, "approver-key-1", "approver@test"),
    signIssuer(payload, issuer.privateKey, "issuer-1"));
  // Registry: approver-key-1 belongs to approver@test ONLY.
  const resolver: KeyResolver = {
    getIssuerPublicKey: id => (id === "issuer-1" ? issuer.publicKey : undefined),
    getApproverPublicKey: (principal, keyId) => (principal === "approver@test" && keyId === "approver-key-1" ? approver.publicKey : undefined),
  };
  return { payload, envelope, issuer, approver, resolver };
}
export const ctx = (over: Partial<VerificationContext> = {}): VerificationContext => ({
  now: NOW, revokedIssuerKeyIds: new Set(), knownApprovers: new Set(["approver@test", "other@test", "sponsor@test", "owner@test"]),
  presented: PRESENTED, ...over });
