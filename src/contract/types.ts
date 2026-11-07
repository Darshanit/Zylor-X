// Field names and signing contexts follow Effect Contract v0.2 exactly.
export const CONTRACT_API_VERSION = "example.invalid/v0.2" as const;
export const SIGNING_ALGORITHM = "Ed25519" as const;
export const HASH_ALGORITHM = "SHA-256" as const;
export const APPROVAL_CONTEXT = "example.invalid/v0.2/approval" as const;
export const ISSUANCE_CONTEXT = "example.invalid/v0.2/issuance" as const;
export type SignatureContext = typeof APPROVAL_CONTEXT | typeof ISSUANCE_CONTEXT;

export type ActorType = "human" | "ci" | "agent" | "workload";

export interface Effect {
  effectId: string; operation: string; resourceType: string; resourceId: string;
  constraints?: Record<string, unknown>; impliedBy?: string;
}
export interface TerraformBinding {
  planHash: string; savedPlanArtifact: string; state: { lineage: string; serial: string };
}
export interface ContractPayload {
  apiVersion: typeof CONTRACT_API_VERSION;
  metadata: { contractId: string; changeId: string; createdAt: string; expiresAt: string; nonce: string };
  issuer: { id: string; keyId: string };
  sponsor: { principal: string; team?: string;
             approval: { type: "human" | "standing-template"; requiredApprover: string } };
  actor: { type: ActorType; identity: string; owner: string; workloadIdentity?: string };
  source: { repository: string; commit: string; workflow?: string; terraform?: TerraformBinding;
            artifact?: { uri: string; digest: string } };
  target: { environment: "sandbox" | "staging" | "production"; cloud: "aws";
            account: string; region: string; cluster?: string };
  effects: Effect[];
  constraints: { maxResourcesAffected?: number; allowIamEffects: boolean; allowRbacEffects: boolean;
                 allowDestructiveEffects: boolean; allowedRegions?: string[] };
  forbiddenOperations: string[];
  recovery: { classification: "reversible" | "compensable" | "irreversible" };
  authorization: { mode: "brokered"; sourceIdentity: string };
  evidence: { signingAlgorithm: typeof SIGNING_ALGORITHM; hashAlgorithm: typeof HASH_ALGORITHM;
              transparency?: { mode: string } };
}
export interface SignatureBlock {
  algorithm: typeof SIGNING_ALGORITHM; signedHash: string; value: string;
}
export interface ContractEnvelope {
  payload: ContractPayload;
  signatures: {
    contractHash: string; // "sha256:<hex>", always recomputed by the verifier
    approval: { signer: string; keyId: string; signature: SignatureBlock };
    issuer: { keyId: string; signature: SignatureBlock };
  };
}

/** What the caller actually presents at issuance time. Everything here is fail-closed. */
export interface Presented {
  planHash?: string | undefined;
  state?: { lineage: string; serial: string } | undefined;
  target?: { account: string; region: string } | undefined;
}
export interface VerificationContext {
  now: Date;
  revokedIssuerKeyIds: ReadonlySet<string>;
  knownApprovers: ReadonlySet<string>;
  presented: Presented;
}
export type VerificationCode =
  | "OK" | "HASH_MISMATCH" | "BAD_APPROVAL_SIGNATURE" | "BAD_ISSUER_SIGNATURE" | "ALGORITHM_MISMATCH"
  | "REVOKED_ISSUER" | "ISSUER_KEY_MISMATCH" | "UNKNOWN_APPROVER" | "UNSUPPORTED_APPROVAL_TYPE"
  | "SEPARATION_OF_DUTIES" | "EXPIRED" | "NOT_YET_VALID" | "INVALID_TIMESTAMP" | "NONCE_MISSING"
  | "PLAN_MISSING" | "PLAN_MISMATCH" | "STATE_MISSING" | "STATE_MISMATCH"
  | "TARGET_MISSING" | "TARGET_MISMATCH" | "REGION_NOT_ALLOWED" | "SOURCE_IDENTITY_MISMATCH" | "MALFORMED";
export interface VerificationResult { ok: boolean; code: VerificationCode; contractHash?: string; reason?: string; }
