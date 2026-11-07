/** Minimal CloudTrail record shape (management events). Synthetic fixtures must be replaced with real sandbox events. */
export interface CloudTrailEvent {
  eventID?: string; eventTime: string; eventSource: string; eventName: string; awsRegion: string;
  recipientAccountId?: string; readOnly?: boolean; errorCode?: string; errorMessage?: string;
  userIdentity: { type?: string; arn?: string; accountId?: string; invokedBy?: string;
    sessionContext?: { sourceIdentity?: string; sessionIssuer?: { arn?: string } } };
  requestParameters?: unknown; responseElements?: unknown;
}
export type Category = "iam" | "storage" | "network" | "compute";
/** Same vocabulary as contract Effect.operation, so observed and contracted effects are comparable. */
export type EffectOperation = "create" | "update" | "delete";
export type Reversibility = "reversible" | "compensable" | "irreversible";
export type Flag = "SENSITIVE_IAM" | "PRIVILEGE_ESCALATION" | "TRUST_POLICY_CHANGE" | "WILDCARD_PRINCIPAL"
  | "PUBLIC_EXPOSURE" | "RECOVERY_WEAKENED" | "WORLD_OPEN_INGRESS" | "UNPARSED_POLICY";

export const UNRESOLVED = "UNRESOLVED"; // resource id not present in the event (typical for denied creates)

export interface EffectDraft {
  operation: EffectOperation; resourceType: string; resourceId: string;
  reversibility: Reversibility; destructive?: boolean; flags?: Flag[]; attributes?: Record<string, string>;
}
export interface ObservedEffect extends EffectDraft {
  apiAction: string;       // e.g. "iam:CreateRole" (matched against forbiddenOperations)
  category: Category; global: boolean; destructive: boolean; flags: Flag[];
}
export interface CatalogEntry {
  eventSource: string; eventName: string; apiAction: string; category: Category;
  /** Global services (IAM) log in us-east-1 regardless of the contract region. */
  global?: boolean;
  extract(ev: CloudTrailEvent, ctx: { account: string }): EffectDraft[];
}
export type Outcome = "SUCCEEDED" | "DENIED" | "FAILED";
export interface Observation {
  eventId: string; eventTime: string; account: string; region: string;
  actorArn?: string; actorType?: string; invokedBy?: string; sourceIdentity?: string;
  outcome: Outcome; errorCode?: string; apiAction: string;
  mapped: boolean; readOnly: boolean; effects: ObservedEffect[]; error?: string;
}
export type EffectClass = "EXPECTED" | "UNATTESTED" | "ORPHAN" | "ATTEMPTED-DENIED" | "UNRELATED-DENIAL"
  | "BUG-DENIED-IN-CONTRACT" | "TRUSTED-SERVICE" | "READ" | "NO-EFFECT";
export interface Classified {
  class: EffectClass; reasons: string[]; flags: Flag[]; apiAction: string; eventId: string;
  changeId?: string; effect?: ObservedEffect;
}
