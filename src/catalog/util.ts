export const get = (o: unknown, path: string): unknown =>
  path.split(".").reduce<unknown>((a, k) => (a !== null && typeof a === "object" ? (a as Record<string, unknown>)[k] : undefined), o);
export const str = (o: unknown, path: string): string | undefined => { const v = get(o, path); return typeof v === "string" && v !== "" ? v : undefined; };
export const need = (o: unknown, path: string): string => { const v = str(o, path); if (v === undefined) throw new Error(`missing ${path}`); return v; };
/** CloudTrail EC2 lists look like { items: [...] }. */
export const items = (o: unknown, path: string): unknown[] => { const v = get(o, path + ".items"); return Array.isArray(v) ? v : []; };
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

export function parsePolicy(doc: unknown): { Statement?: unknown } | undefined {
  if (typeof doc !== "string") return doc !== null && typeof doc === "object" ? doc as { Statement?: unknown } : undefined;
  for (const t of [doc, (() => { try { return decodeURIComponent(doc); } catch { return ""; } })()]) {
    try { const p = JSON.parse(t); if (p && typeof p === "object") return p; } catch { /* try next */ }
  }
  return undefined;
}
const statements = (doc: unknown): Record<string, unknown>[] => {
  const s = parsePolicy(doc)?.Statement; return (Array.isArray(s) ? s : s ? [s] : []) as Record<string, unknown>[];
};
export const policyIsAdmin = (doc: unknown) =>
  statements(doc).some(s => s["Effect"] === "Allow" && arr(s["Action"]).includes("*") && arr(s["Resource"]).includes("*"));
export const hasWildcardPrincipal = (doc: unknown) =>
  statements(doc).some(s => s["Effect"] === "Allow" &&
    (s["Principal"] === "*" || arr((s["Principal"] as Record<string, unknown> | undefined)?.["AWS"]).includes("*")));
export const policyParsed = (doc: unknown) => parsePolicy(doc) !== undefined;
