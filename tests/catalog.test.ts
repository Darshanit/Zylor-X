import { describe, it, expect } from "vitest";
import { CATALOG, classifyEvent, normalizeEvent, outcomeOf, UNRESOLVED, type ContractLookup } from "../src/catalog/index.js";
import type { ContractPayload } from "../src/contract/types.js";
import { makePayload } from "./helpers.js";
import { ev, F } from "./fixtures/cloudtrail.js";

const lookup = (p: ContractPayload): ContractLookup => ({ get: id => (id === p.authorization.sourceIdentity ? p : undefined) });
const contract = (effects: ContractPayload["effects"], edit?: (p: ContractPayload) => void) => { const p = makePayload(); p.effects = effects; edit?.(p); return lookup(p); };
const fx = (operation: string, resourceType: string, resourceId: string) => ({ effectId: "E", operation, resourceType, resourceId });
const one = (e: Parameters<typeof classifyEvent>[0], c: ContractLookup, o?: Parameters<typeof classifyEvent>[2]) => classifyEvent(e, c, o)[0]!;

describe("catalog normalization (15 mappings)", () => {
  const cases: [string, ReturnType<typeof F.createRole>, string, string, string, string][] = [
    ["CreateRole", F.createRole(), "create", "aws.iam.role", "evil", "iam:CreateRole"],
    ["AttachRolePolicy", F.attachAdmin(), "create", "aws.iam.role_policy_attachment", "evil/arn:aws:iam::aws:policy/AdministratorAccess", "iam:AttachRolePolicy"],
    ["PutRolePolicy", F.putRolePolicy(), "update", "aws.iam.role_policy", "r1:p1", "iam:PutRolePolicy"],
    ["UpdateAssumeRolePolicy", F.updateTrust(), "update", "aws.iam.role", "r1", "iam:UpdateAssumeRolePolicy"],
    ["CreatePolicyVersion", F.createPolicyVersion(), "update", "aws.iam.policy", "arn:aws:iam::111111111111:policy/p1", "iam:CreatePolicyVersion"],
    ["CreateBucket", F.createBucket(), "create", "aws.s3.bucket", "app-bucket", "s3:CreateBucket"],
    ["PutBucketPolicy", F.putBucketPolicyPublic(), "update", "aws.s3.bucket_policy", "app-bucket", "s3:PutBucketPolicy"],
    ["PutPublicAccessBlock", F.putPab({ BlockPublicAcls: true }), "update", "aws.s3.bucket_public_access_block", "app-bucket", "s3:PutPublicAccessBlock"],
    ["PutBucketVersioning", F.putVersioning("Enabled"), "update", "aws.s3.bucket_versioning", "app-bucket", "s3:PutBucketVersioning"],
    ["DeleteBucket", F.deleteBucket(), "delete", "aws.s3.bucket", "app-bucket", "s3:DeleteBucket"],
    ["RunInstances", F.runInstances(["i-1"]), "create", "aws.ec2.instance", "i-1", "ec2:RunInstances"],
    ["TerminateInstances", F.terminate(["i-1"]), "delete", "aws.ec2.instance", "i-1", "ec2:TerminateInstances"],
    ["CreateSecurityGroup", F.createSg(), "create", "aws.ec2.security_group", "sg-1", "ec2:CreateSecurityGroup"],
    ["AuthorizeSecurityGroupIngress", F.openIngress(), "create", "aws.ec2.security_group_rule", "sg-1", "ec2:AuthorizeSecurityGroupIngress"],
    ["RevokeSecurityGroupIngress", F.revokeIngress(), "delete", "aws.ec2.security_group_rule", "sg-1", "ec2:RevokeSecurityGroupIngress"],
  ];
  it("catalog has exactly the 15 starter entries", () => expect(CATALOG.length).toBe(15));
  it.each(cases)("%s", (_n, e, op, type, id, action) => {
    const o = normalizeEvent(e); expect(o.mapped).toBe(true); expect(o.error).toBeUndefined();
    expect(o.effects[0]).toMatchObject({ operation: op, resourceType: type, resourceId: id, apiAction: action });
  });
  it("one effect per instance for multi-instance RunInstances / TerminateInstances", () => {
    expect(normalizeEvent(F.runInstances(["i-1", "i-2", "i-3"])).effects.map(e => e.resourceId)).toEqual(["i-1", "i-2", "i-3"]);
    expect(normalizeEvent(F.terminate(["i-1", "i-2"])).effects.length).toBe(2); });
  it("denied RunInstances has no ids: resource is UNRESOLVED", () =>
    expect(normalizeEvent(F.runInstances([], { errorCode: "Client.UnauthorizedOperation" })).effects[0]?.resourceId).toBe(UNRESOLVED));
  it("flags: admin policy attach, wildcard trust, public bucket policy, world-open ingress, versioning off, PAB weakened", () => {
    expect(normalizeEvent(F.attachAdmin()).effects[0]?.flags).toContain("PRIVILEGE_ESCALATION");
    expect(normalizeEvent(F.createRole()).effects[0]?.flags).toEqual(expect.arrayContaining(["WILDCARD_PRINCIPAL", "TRUST_POLICY_CHANGE"]));
    expect(normalizeEvent(F.putRolePolicy()).effects[0]?.flags).toContain("PRIVILEGE_ESCALATION");
    expect(normalizeEvent(F.putBucketPolicyPublic()).effects[0]?.flags).toContain("PUBLIC_EXPOSURE");
    expect(normalizeEvent(F.openIngress()).effects[0]?.flags).toContain("WORLD_OPEN_INGRESS");
    expect(normalizeEvent(F.closedIngress()).effects[0]?.flags).not.toContain("WORLD_OPEN_INGRESS");
    expect(normalizeEvent(F.putVersioning("Suspended")).effects[0]?.flags).toContain("RECOVERY_WEAKENED");
    expect(normalizeEvent(F.putPab({ BlockPublicAcls: false })).effects[0]?.flags).toContain("PUBLIC_EXPOSURE");
    expect(normalizeEvent(F.putPab({ BlockPublicAcls: true, IgnorePublicAcls: true })).effects[0]?.flags).not.toContain("PUBLIC_EXPOSURE"); });
  it("destructive + irreversible marking", () => {
    expect(normalizeEvent(F.deleteBucket()).effects[0]).toMatchObject({ destructive: true, reversibility: "irreversible" });
    expect(normalizeEvent(F.terminate(["i-1"])).effects[0]).toMatchObject({ destructive: true, reversibility: "irreversible" }); });
  it("unparseable policy document is flagged", () => {
    const e = ev("iam.amazonaws.com", "PutRolePolicy", { awsRegion: "us-east-1", requestParameters: { roleName: "r", policyName: "p", policyDocument: "%%not json%%" } });
    expect(normalizeEvent(e).effects[0]?.flags).toContain("UNPARSED_POLICY"); });
  it("denied-code detection", () => {
    for (const c of ["AccessDenied", "Client.UnauthorizedOperation", "AccessDeniedException"]) expect(outcomeOf(ev("iam.amazonaws.com", "CreateRole", { errorCode: c }))).toBe("DENIED");
    expect(outcomeOf(ev("iam.amazonaws.com", "CreateRole", { errorCode: "EntityAlreadyExists" }))).toBe("FAILED");
    expect(outcomeOf(ev("iam.amazonaws.com", "CreateRole"))).toBe("SUCCEEDED"); });
  it("unmapped mutating API is kept, not dropped", () => {
    const o = normalizeEvent(ev("kms.amazonaws.com", "ScheduleKeyDeletion")); expect(o.mapped).toBe(false); expect(o.apiAction).toBe("kms:ScheduleKeyDeletion"); });
  it("malformed mapped event records a normalization error instead of throwing", () => {
    const o = normalizeEvent(ev("s3.amazonaws.com", "CreateBucket", { requestParameters: {} })); expect(o.error).toMatch(/bucketName/); });
});

describe("classification against a contract", () => {
  const bucketContract = () => contract([fx("create", "aws.s3.bucket", "app-bucket")]);
  it("in-contract brokered success -> EXPECTED", () => expect(one(F.createBucket(), bucketContract()).class).toBe("EXPECTED"));
  it("wildcard resource id in contract matches", () => expect(one(F.createBucket(), contract([fx("create", "aws.s3.bucket", "app-*")])).class).toBe("EXPECTED"));
  it("different resource -> UNATTESTED NOT_IN_CONTRACT", () => {
    const r = one(F.createBucket(), contract([fx("create", "aws.s3.bucket", "other")])); expect(r.class).toBe("UNATTESTED"); expect(r.reasons).toContain("NOT_IN_CONTRACT"); });
  it("A01: CreateRole + AttachRolePolicy(Admin) under a bucket-only contract -> UNATTESTED with escalation flag", () => {
    const c = bucketContract(); const a = one(F.createRole(), c), b = one(F.attachAdmin(), c);
    expect(a.class).toBe("UNATTESTED"); expect(a.reasons).toEqual(expect.arrayContaining(["NOT_IN_CONTRACT", "IAM_NOT_ALLOWED"]));
    expect(b.class).toBe("UNATTESTED"); expect(b.flags).toContain("PRIVILEGE_ESCALATION"); });
  it("IAM effect listed in contract but allowIamEffects=false is still a violation", () => {
    const c = contract([fx("create", "aws.iam.role", "evil")], p => { p.forbiddenOperations = []; }); const r = one(F.createRole(), c); expect(r.class).toBe("UNATTESTED"); expect(r.reasons).toEqual(["IAM_NOT_ALLOWED"]); });
  it("effect listed but also in forbiddenOperations -> UNATTESTED FORBIDDEN_OPERATION", () => {
    const c = contract([fx("create", "aws.iam.role", "evil")], p => { p.constraints.allowIamEffects = true; p.forbiddenOperations = ["iam:CreateRole"]; });
    expect(one(F.createRole(), c).reasons).toContain("FORBIDDEN_OPERATION"); });
  it("destructive effect blocked unless allowDestructiveEffects", () => {
    const e = [fx("delete", "aws.s3.bucket", "app-bucket")];
    expect(one(F.deleteBucket(), contract(e)).reasons).toContain("DESTRUCTIVE_NOT_ALLOWED");
    expect(one(F.deleteBucket(), contract(e, p => { p.constraints.allowDestructiveEffects = true; })).class).toBe("EXPECTED"); });
  it("no SourceIdentity on a successful mutation -> ORPHAN (A04/A32)", () => {
    const r = one(F.createRole({ si: null }), bucketContract()); expect(r.class).toBe("ORPHAN"); expect(r.reasons).toContain("NO_SOURCE_IDENTITY"); });
  it("SourceIdentity with no known contract -> ORPHAN UNKNOWN_CHANGE_ID", () =>
    expect(one(F.createBucket({ si: "CHG-NOPE" }), bucketContract()).reasons).toContain("UNKNOWN_CHANGE_ID"));
  it("event outside the contract's active window -> ORPHAN", () => {
    const r = one(F.createBucket({ eventTime: "2026-10-02T00:00:00Z" }), bucketContract()); expect(r.class).toBe("ORPHAN"); expect(r.reasons).toContain("CONTRACT_NOT_ACTIVE_AT_EVENT_TIME"); });
  it("trusted service actor without SourceIdentity -> TRUSTED-SERVICE, otherwise ORPHAN", () => {
    const e = F.createSg({ si: null, userIdentity: { type: "AWSService", invokedBy: "autoscaling.amazonaws.com", accountId: "111111111111" } });
    expect(one(e, bucketContract(), { trustedActors: new Set(["autoscaling.amazonaws.com"]) }).class).toBe("TRUSTED-SERVICE");
    expect(one(e, bucketContract()).class).toBe("ORPHAN"); });
  it("wrong account -> UNATTESTED WRONG_ACCOUNT (A28)", () =>
    expect(one(F.createBucket({ recipientAccountId: "999999999999" }), bucketContract()).reasons).toContain("WRONG_ACCOUNT"));
  it("wrong region -> REGION_NOT_ALLOWED, but global IAM events in us-east-1 are not a region violation", () => {
    expect(one(F.createBucket({ awsRegion: "eu-west-1" }), bucketContract()).reasons).toContain("REGION_NOT_ALLOWED");
    const c = contract([fx("create", "aws.iam.role", "evil")], p => { p.constraints.allowIamEffects = true; p.forbiddenOperations = []; });
    expect(one(F.createRole(), c).class).toBe("EXPECTED"); });
  it("unmapped mutating API under a valid contract -> UNATTESTED UNMAPPED_API (never silently EXPECTED)", () => {
    const r = one(ev("kms.amazonaws.com", "ScheduleKeyDeletion"), bucketContract()); expect(r.class).toBe("UNATTESTED"); expect(r.reasons).toContain("UNMAPPED_API"); });
  it("unmapped mutating API without SourceIdentity -> ORPHAN", () => expect(one(ev("kms.amazonaws.com", "ScheduleKeyDeletion", { si: null }), bucketContract()).class).toBe("ORPHAN"));
  it("unmapped read-only API -> READ", () => expect(one(ev("s3.amazonaws.com", "ListBuckets", { readOnly: true }), bucketContract()).class).toBe("READ"));
  it("non-denial failure -> NO-EFFECT", () => expect(one(F.createRole({ errorCode: "EntityAlreadyExists" }), bucketContract()).class).toBe("NO-EFFECT"));
  it("normalization error on a successful event is not EXPECTED", () => {
    const r = one(ev("s3.amazonaws.com", "CreateBucket", { requestParameters: {} }), bucketContract()); expect(r.class).toBe("UNATTESTED"); expect(r.reasons).toContain("NORMALIZATION_ERROR"); });
  it("multi-instance RunInstances: each instance classified separately", () => {
    const rs = classifyEvent(F.runInstances(["i-1", "i-2"]), contract([fx("create", "aws.ec2.instance", "i-1")]));
    expect(rs.map(r => r.class)).toEqual(["EXPECTED", "UNATTESTED"]); });
});

describe("denied events (A01 / A44 semantics)", () => {
  const denied = { errorCode: "AccessDenied", errorMessage: "not authorized" };
  const bucketContract = () => contract([fx("create", "aws.s3.bucket", "app-bucket")]);
  it("denied + matching SourceIdentity + out-of-contract -> ATTEMPTED-DENIED", () => {
    const r = one(F.createRole(denied), bucketContract()); expect(r.class).toBe("ATTEMPTED-DENIED"); expect(r.changeId).toBe("CHG-1"); });
  it("denied + no SourceIdentity -> UNRELATED-DENIAL", () => expect(one(F.createRole({ ...denied, si: null }), bucketContract()).class).toBe("UNRELATED-DENIAL"));
  it("denied + unknown change id -> UNRELATED-DENIAL", () => expect(one(F.createRole({ ...denied, si: "CHG-X" }), bucketContract()).class).toBe("UNRELATED-DENIAL"));
  it("denied but in-contract -> BUG-DENIED-IN-CONTRACT (compiler/session-policy bug)", () =>
    expect(one(F.createBucket(denied), bucketContract()).class).toBe("BUG-DENIED-IN-CONTRACT"));
  it("denied attempt at a forbidden op even if listed -> ATTEMPTED-DENIED", () => {
    const c = contract([fx("create", "aws.iam.role", "evil")], p => { p.constraints.allowIamEffects = true; p.forbiddenOperations = ["iam:CreateRole"]; });
    expect(one(F.createRole(denied), c).class).toBe("ATTEMPTED-DENIED"); });
  it("denied EC2 RunInstances (UNRESOLVED id) outside contract -> ATTEMPTED-DENIED", () =>
    expect(one(F.runInstances([], { errorCode: "Client.UnauthorizedOperation" }), bucketContract()).class).toBe("ATTEMPTED-DENIED"));
  it("denied unmapped API with active contract -> ATTEMPTED-DENIED UNMAPPED_API", () => {
    const r = one(ev("kms.amazonaws.com", "ScheduleKeyDeletion", denied), bucketContract()); expect(r.class).toBe("ATTEMPTED-DENIED"); expect(r.reasons).toContain("UNMAPPED_API"); });
});
