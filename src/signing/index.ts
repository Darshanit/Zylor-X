import canonicalizeModule from "canonicalize";
import { createHash, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { APPROVAL_CONTEXT, CONTRACT_API_VERSION, HASH_ALGORITHM, ISSUANCE_CONTEXT, SIGNING_ALGORITHM,
  type ContractEnvelope, type ContractPayload, type SignatureBlock, type SignatureContext } from "../contract/types.js";
const canonicalize = canonicalizeModule as unknown as (v: unknown) => string | undefined;

/** RFC 8785 canonical bytes of the payload (signatures are never part of it). */
export function canonicalPayload(payload: ContractPayload): Buffer {
  const json = canonicalize(payload);
  if (json === undefined) throw new Error("Payload is not RFC 8785 canonicalizable");
  return Buffer.from(json, "utf8");
}
/** contractHash = "sha256:" + lowercase hex of SHA-256(canonical payload). */
export function hashPayload(payload: ContractPayload): string {
  return "sha256:" + createHash("sha256").update(canonicalPayload(payload)).digest("hex");
}
/** Exact signed bytes: UTF-8( context + "\n" + contractHash ). */
export function signingBytes(context: SignatureContext, contractHash: string): Buffer {
  return Buffer.from(`${context}\n${contractHash}`, "utf8");
}
export function createKeyPair() { return generateKeyPairSync("ed25519"); }

function makeSig(context: SignatureContext, payload: ContractPayload, key: KeyObject): SignatureBlock {
  const h = hashPayload(payload);
  return { algorithm: SIGNING_ALGORITHM, signedHash: h, value: sign(null, signingBytes(context, h), key).toString("base64") };
}
export function signApproval(payload: ContractPayload, key: KeyObject, keyId: string, signer: string) {
  return { signer, keyId, signature: makeSig(APPROVAL_CONTEXT, payload, key) };
}
export function signIssuer(payload: ContractPayload, key: KeyObject, keyId: string) {
  return { keyId, signature: makeSig(ISSUANCE_CONTEXT, payload, key) };
}
export function verifySignature(s: SignatureBlock, key: KeyObject, context: SignatureContext, hash: string): boolean {
  return s.algorithm === SIGNING_ALGORITHM && s.signedHash === hash &&
    verify(null, signingBytes(context, hash), key, Buffer.from(s.value, "base64"));
}
export function assertSupportedAlgorithm(p: ContractPayload) {
  if (p.apiVersion !== CONTRACT_API_VERSION || p.evidence.signingAlgorithm !== SIGNING_ALGORITHM ||
      p.evidence.hashAlgorithm !== HASH_ALGORITHM) throw new Error("Unsupported contract/signing algorithm");
}
export function buildEnvelope(payload: ContractPayload, approval: ContractEnvelope["signatures"]["approval"],
  issuer: ContractEnvelope["signatures"]["issuer"]): ContractEnvelope {
  return { payload, signatures: { contractHash: hashPayload(payload), approval, issuer } };
}
