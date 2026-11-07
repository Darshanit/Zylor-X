import type { ContractEnvelope } from "../contract/types.js";
import { parseStrictJson, StrictParseError } from "./strict.js";
export { parseStrictJson, StrictParseError } from "./strict.js";

const get = (o: unknown, path: string): unknown =>
  path.split(".").reduce<unknown>((a, k) => (a !== null && typeof a === "object" ? (a as Record<string, unknown>)[k] : undefined), o);
const STRINGS = [
  "payload.apiVersion", "payload.metadata.contractId", "payload.metadata.changeId", "payload.metadata.createdAt",
  "payload.metadata.expiresAt", "payload.metadata.nonce", "payload.issuer.id", "payload.issuer.keyId",
  "payload.sponsor.principal", "payload.sponsor.approval.type", "payload.sponsor.approval.requiredApprover",
  "payload.actor.type", "payload.actor.identity", "payload.actor.owner", "payload.source.repository",
  "payload.source.commit", "payload.target.environment", "payload.target.cloud", "payload.target.account",
  "payload.target.region", "payload.recovery.classification", "payload.authorization.mode",
  "payload.authorization.sourceIdentity", "payload.evidence.signingAlgorithm", "payload.evidence.hashAlgorithm",
  "signatures.contractHash", "signatures.approval.signer", "signatures.approval.keyId",
  "signatures.approval.signature.algorithm", "signatures.approval.signature.signedHash", "signatures.approval.signature.value",
  "signatures.issuer.keyId", "signatures.issuer.signature.algorithm", "signatures.issuer.signature.signedHash",
  "signatures.issuer.signature.value"];
const BOOLS = ["payload.constraints.allowIamEffects", "payload.constraints.allowRbacEffects", "payload.constraints.allowDestructiveEffects"];

/** Shape check so the verifier never dereferences undefined on attacker-controlled input. */
export function assertEnvelopeShape(x: unknown): asserts x is ContractEnvelope {
  const bad = (m: string): never => { throw new StrictParseError("SHAPE", m); };
  for (const p of STRINGS) if (typeof get(x, p) !== "string") bad(`${p} must be a string`);
  for (const p of BOOLS) if (typeof get(x, p) !== "boolean") bad(`${p} must be a boolean`);
  const effects = get(x, "payload.effects");
  if (!Array.isArray(effects)) bad("payload.effects must be an array");
  for (const [n, e] of (effects as unknown[]).entries())
    for (const f of ["effectId", "operation", "resourceType", "resourceId"])
      if (typeof get(e, f) !== "string") bad(`payload.effects[${n}].${f} must be a string`);
  const fo = get(x, "payload.forbiddenOperations");
  if (!Array.isArray(fo) || fo.some(s => typeof s !== "string")) bad("payload.forbiddenOperations must be string[]");
  const ar = get(x, "payload.constraints.allowedRegions");
  if (ar !== undefined && (!Array.isArray(ar) || ar.some(s => typeof s !== "string"))) bad("allowedRegions must be string[]");
  const tf = get(x, "payload.source.terraform");
  if (tf !== undefined)
    for (const f of ["planHash", "savedPlanArtifact", "state.lineage", "state.serial"])
      if (typeof get(tf, f) !== "string") bad(`payload.source.terraform.${f} must be a string`);
}
/** Untrusted text -> validated envelope. Throws StrictParseError on anything suspicious. */
export function parseEnvelope(text: string): ContractEnvelope {
  const v = parseStrictJson(text);
  assertEnvelopeShape(v);
  return v;
}
