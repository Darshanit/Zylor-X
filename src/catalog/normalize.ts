import { CATALOG_INDEX } from "./entries.js";
import type { CloudTrailEvent, Observation, ObservedEffect, Outcome } from "./types.js";

export const DENIED_CODES: ReadonlySet<string> = new Set(["AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
  "Client.UnauthorizedOperation", "UnauthorizedAccess"]);
export function outcomeOf(ev: CloudTrailEvent): Outcome {
  if (!ev.errorCode) return "SUCCEEDED";
  return DENIED_CODES.has(ev.errorCode) ? "DENIED" : "FAILED";
}
const service = (src: string) => src.replace(/\.amazonaws\.com$/, "");

/** CloudTrail record -> Observation. Unknown mutating APIs are kept (mapped=false), never dropped. */
export function normalizeEvent(ev: CloudTrailEvent): Observation {
  const entry = CATALOG_INDEX.get(`${ev.eventSource}|${ev.eventName}`);
  const account = ev.recipientAccountId ?? ev.userIdentity?.accountId ?? "unknown";
  const si = ev.userIdentity?.sessionContext?.sourceIdentity;
  const base: Observation = {
    eventId: ev.eventID ?? `${ev.eventTime}|${ev.eventName}`, eventTime: ev.eventTime, account, region: ev.awsRegion,
    outcome: outcomeOf(ev), apiAction: entry?.apiAction ?? `${service(ev.eventSource)}:${ev.eventName}`,
    mapped: !!entry, readOnly: ev.readOnly === true, effects: [],
    ...(ev.userIdentity?.arn ? { actorArn: ev.userIdentity.arn } : {}),
    ...(ev.userIdentity?.type ? { actorType: ev.userIdentity.type } : {}),
    ...(ev.userIdentity?.invokedBy ? { invokedBy: ev.userIdentity.invokedBy } : {}),
    ...(si ? { sourceIdentity: si } : {}),
    ...(ev.errorCode ? { errorCode: ev.errorCode } : {}),
  };
  if (!entry) return base;
  try {
    const effects: ObservedEffect[] = entry.extract(ev, { account }).map(d => ({
      ...d, apiAction: entry.apiAction, category: entry.category, global: entry.global === true,
      destructive: d.destructive === true, flags: d.flags ?? [] }));
    return { ...base, effects };
  } catch (e) { return { ...base, error: String(e instanceof Error ? e.message : e) }; }
}
