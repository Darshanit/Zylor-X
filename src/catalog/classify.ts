import type { ContractPayload } from "../contract/types.js";
import { normalizeEvent } from "./normalize.js";
import type { Classified, CloudTrailEvent, EffectClass, Flag, Observation, ObservedEffect } from "./types.js";
import { UNRESOLVED } from "./types.js";

export interface ContractLookup { get(changeId: string): ContractPayload | undefined; }
export interface ClassifyOptions { trustedActors?: ReadonlySet<string>; }

function resourceMatches(contracted: string, observed: string): boolean {
  if (observed === UNRESOLVED) return true; // identity unknown (e.g. denied create): decided by operation + type
  if (contracted === "*") return true;
  return contracted.endsWith("*") ? observed.startsWith(contracted.slice(0, -1)) : contracted === observed;
}
function inContract(c: ContractPayload, e: ObservedEffect): boolean {
  return c.effects.some(x => x.operation === e.operation && x.resourceType === e.resourceType && resourceMatches(x.resourceId, e.resourceId));
}
function violations(c: ContractPayload, o: Observation, e: ObservedEffect | undefined): string[] {
  const v: string[] = [];
  if (o.account !== c.target.account) v.push("WRONG_ACCOUNT");
  if (!e) { v.push(o.error ? "NORMALIZATION_ERROR" : "UNMAPPED_API"); return v; }
  if (!e.global && o.region !== c.target.region && !(c.constraints.allowedRegions ?? []).includes(o.region)) v.push("REGION_NOT_ALLOWED");
  if (c.forbiddenOperations.includes(e.apiAction)) v.push("FORBIDDEN_OPERATION");
  if (!inContract(c, e)) v.push("NOT_IN_CONTRACT");
  if (e.category === "iam" && !c.constraints.allowIamEffects) v.push("IAM_NOT_ALLOWED");
  if (e.destructive && !c.constraints.allowDestructiveEffects) v.push("DESTRUCTIVE_NOT_ALLOWED");
  return v;
}
export function classifyObservation(o: Observation, contracts: ContractLookup, opts: ClassifyOptions = {}): Classified[] {
  const mk = (cls: EffectClass, reasons: string[], e?: ObservedEffect, changeId?: string): Classified =>
    ({ class: cls, reasons, flags: e?.flags ?? [] as Flag[], apiAction: o.apiAction, eventId: o.eventId,
       ...(changeId ? { changeId } : {}), ...(e ? { effect: e } : {}) });
  if (o.readOnly && !o.mapped) return [mk("READ", [])];
  if (o.outcome === "FAILED") return [mk("NO-EFFECT", [`NON_DENIAL_ERROR:${o.errorCode ?? "unknown"}`])];

  const si = o.sourceIdentity, contract = si ? contracts.get(si) : undefined;
  const t = Date.parse(o.eventTime);
  const active = !!contract && t >= Date.parse(contract.metadata.createdAt) && t < Date.parse(contract.metadata.expiresAt);
  const noContractReason = !si ? "NO_SOURCE_IDENTITY" : !contract ? "UNKNOWN_CHANGE_ID" : "CONTRACT_NOT_ACTIVE_AT_EVENT_TIME";
  const effects: (ObservedEffect | undefined)[] = o.effects.length ? o.effects : [undefined];

  return effects.map(e => {
    if (o.outcome === "DENIED") {
      if (!active || !contract) return mk("UNRELATED-DENIAL", [noContractReason], e, si);
      const v = violations(contract, o, e);
      return v.length ? mk("ATTEMPTED-DENIED", v, e, si) : mk("BUG-DENIED-IN-CONTRACT", ["DENIED_BUT_IN_CONTRACT"], e, si);
    }
    if (!active || !contract) {
      const trusted = !si && !!opts.trustedActors && ((o.actorArn !== undefined && opts.trustedActors.has(o.actorArn)) ||
        (o.invokedBy !== undefined && opts.trustedActors.has(o.invokedBy)));
      if (trusted) return mk("TRUSTED-SERVICE", [], e);
      return mk("ORPHAN", [noContractReason, ...(e ? [] : [o.error ? "NORMALIZATION_ERROR" : "UNMAPPED_API"])], e, si);
    }
    const v = violations(contract, o, e);
    return v.length ? mk("UNATTESTED", v, e, si) : mk("EXPECTED", [], e, si);
  });
}
export const classifyEvent = (ev: CloudTrailEvent, contracts: ContractLookup, opts?: ClassifyOptions) =>
  classifyObservation(normalizeEvent(ev), contracts, opts);
