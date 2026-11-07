import type { CatalogEntry, EffectDraft, Flag } from "./types.js";
import { UNRESOLVED } from "./types.js";
import { get, hasWildcardPrincipal, items, need, policyIsAdmin, policyParsed, str } from "./util.js";

/**
 * Resource-id convention: the provider-native id that Terraform uses as `id`
 * (IAM role -> name, S3 bucket -> name, EC2 -> i-/sg- ids, IAM policy -> ARN),
 * so contracts derived from plans compare directly with observed effects.
 */
const ADMIN_POLICY = /\/(AdministratorAccess|IAMFullAccess)$/;
const policyFlags = (doc: unknown, base: Flag[]): Flag[] => {
  const f = [...base];
  if (doc !== undefined && !policyParsed(doc)) f.push("UNPARSED_POLICY");
  if (policyIsAdmin(doc)) f.push("PRIVILEGE_ESCALATION");
  return f;
};
const E = (e: CatalogEntry) => e;

export const CATALOG: CatalogEntry[] = [
  // ---- IAM (global: logged in us-east-1) ----
  E({ eventSource: "iam.amazonaws.com", eventName: "CreateRole", apiAction: "iam:CreateRole", category: "iam", global: true,
    extract: ev => { const d = get(ev.requestParameters, "assumeRolePolicyDocument");
      const flags: Flag[] = ["SENSITIVE_IAM"]; if (hasWildcardPrincipal(d)) flags.push("WILDCARD_PRINCIPAL", "TRUST_POLICY_CHANGE");
      if (d !== undefined && !policyParsed(d)) flags.push("UNPARSED_POLICY");
      return [{ operation: "create", resourceType: "aws.iam.role", resourceId: need(ev.requestParameters, "roleName"), reversibility: "compensable", flags }]; } }),
  E({ eventSource: "iam.amazonaws.com", eventName: "AttachRolePolicy", apiAction: "iam:AttachRolePolicy", category: "iam", global: true,
    extract: ev => { const role = need(ev.requestParameters, "roleName"), arn = need(ev.requestParameters, "policyArn");
      const flags: Flag[] = ["SENSITIVE_IAM"]; if (ADMIN_POLICY.test(arn)) flags.push("PRIVILEGE_ESCALATION");
      return [{ operation: "create", resourceType: "aws.iam.role_policy_attachment", resourceId: `${role}/${arn}`, reversibility: "compensable", flags, attributes: { policyArn: arn } }]; } }),
  E({ eventSource: "iam.amazonaws.com", eventName: "PutRolePolicy", apiAction: "iam:PutRolePolicy", category: "iam", global: true,
    extract: ev => { const role = need(ev.requestParameters, "roleName"), name = need(ev.requestParameters, "policyName");
      return [{ operation: "update", resourceType: "aws.iam.role_policy", resourceId: `${role}:${name}`, reversibility: "compensable",
        flags: policyFlags(get(ev.requestParameters, "policyDocument"), ["SENSITIVE_IAM"]) }]; } }),
  E({ eventSource: "iam.amazonaws.com", eventName: "UpdateAssumeRolePolicy", apiAction: "iam:UpdateAssumeRolePolicy", category: "iam", global: true,
    extract: ev => { const d = get(ev.requestParameters, "policyDocument"); const flags: Flag[] = ["SENSITIVE_IAM", "TRUST_POLICY_CHANGE"];
      if (hasWildcardPrincipal(d)) flags.push("WILDCARD_PRINCIPAL"); if (d !== undefined && !policyParsed(d)) flags.push("UNPARSED_POLICY");
      return [{ operation: "update", resourceType: "aws.iam.role", resourceId: need(ev.requestParameters, "roleName"), reversibility: "compensable", flags }]; } }),
  E({ eventSource: "iam.amazonaws.com", eventName: "CreatePolicyVersion", apiAction: "iam:CreatePolicyVersion", category: "iam", global: true,
    extract: ev => [{ operation: "update", resourceType: "aws.iam.policy", resourceId: need(ev.requestParameters, "policyArn"), reversibility: "compensable",
      flags: policyFlags(get(ev.requestParameters, "policyDocument"), ["SENSITIVE_IAM"]) }] }),
  // ---- S3 ----
  E({ eventSource: "s3.amazonaws.com", eventName: "CreateBucket", apiAction: "s3:CreateBucket", category: "storage",
    extract: ev => [{ operation: "create", resourceType: "aws.s3.bucket", resourceId: need(ev.requestParameters, "bucketName"), reversibility: "reversible" }] }),
  E({ eventSource: "s3.amazonaws.com", eventName: "PutBucketPolicy", apiAction: "s3:PutBucketPolicy", category: "storage",
    extract: ev => { const d = get(ev.requestParameters, "bucketPolicy"); const flags: Flag[] = [];
      if (hasWildcardPrincipal(d)) flags.push("WILDCARD_PRINCIPAL", "PUBLIC_EXPOSURE"); if (d !== undefined && !policyParsed(d)) flags.push("UNPARSED_POLICY");
      return [{ operation: "update", resourceType: "aws.s3.bucket_policy", resourceId: need(ev.requestParameters, "bucketName"), reversibility: "compensable", flags }]; } }),
  E({ eventSource: "s3.amazonaws.com", eventName: "PutPublicAccessBlock", apiAction: "s3:PutPublicAccessBlock", category: "storage",
    extract: ev => { const cfg = get(ev.requestParameters, "PublicAccessBlockConfiguration") as Record<string, unknown> | undefined;
      const weakened = !cfg || Object.values(cfg).some(v => v !== true); // missing or any control not true = weakened/unknown
      return [{ operation: "update", resourceType: "aws.s3.bucket_public_access_block", resourceId: need(ev.requestParameters, "bucketName"),
        reversibility: "compensable", flags: weakened ? ["PUBLIC_EXPOSURE"] as Flag[] : [] }]; } }),
  E({ eventSource: "s3.amazonaws.com", eventName: "PutBucketVersioning", apiAction: "s3:PutBucketVersioning", category: "storage",
    extract: ev => { const status = str(ev.requestParameters, "VersioningConfiguration.Status");
      return [{ operation: "update", resourceType: "aws.s3.bucket_versioning", resourceId: need(ev.requestParameters, "bucketName"), reversibility: "compensable",
        flags: status === "Enabled" ? [] : ["RECOVERY_WEAKENED"] as Flag[], attributes: { status: status ?? "unknown" } }]; } }),
  E({ eventSource: "s3.amazonaws.com", eventName: "DeleteBucket", apiAction: "s3:DeleteBucket", category: "storage",
    extract: ev => [{ operation: "delete", resourceType: "aws.s3.bucket", resourceId: need(ev.requestParameters, "bucketName"), reversibility: "irreversible", destructive: true }] }),
  // ---- EC2 ----
  E({ eventSource: "ec2.amazonaws.com", eventName: "RunInstances", apiAction: "ec2:RunInstances", category: "compute",
    extract: ev => { const ids = items(ev.responseElements, "instancesSet").map(i => str(i, "instanceId")).filter((x): x is string => !!x);
      const itype = str(ev.requestParameters, "instanceType");
      return (ids.length ? ids : [UNRESOLVED]).map((id): EffectDraft => ({ operation: "create", resourceType: "aws.ec2.instance", resourceId: id,
        reversibility: "reversible", ...(itype ? { attributes: { instanceType: itype } } : {}) })); } }),
  E({ eventSource: "ec2.amazonaws.com", eventName: "TerminateInstances", apiAction: "ec2:TerminateInstances", category: "compute",
    extract: ev => { const ids = items(ev.requestParameters, "instancesSet").map(i => str(i, "instanceId")).filter((x): x is string => !!x);
      if (!ids.length) throw new Error("missing instancesSet.items[].instanceId");
      return ids.map((id): EffectDraft => ({ operation: "delete", resourceType: "aws.ec2.instance", resourceId: id, reversibility: "irreversible", destructive: true })); } }),
  E({ eventSource: "ec2.amazonaws.com", eventName: "CreateSecurityGroup", apiAction: "ec2:CreateSecurityGroup", category: "network",
    extract: ev => [{ operation: "create", resourceType: "aws.ec2.security_group", resourceId: str(ev.responseElements, "groupId") ?? UNRESOLVED,
      reversibility: "reversible", attributes: { groupName: str(ev.requestParameters, "groupName") ?? "unknown" } }] }),
  E({ eventSource: "ec2.amazonaws.com", eventName: "AuthorizeSecurityGroupIngress", apiAction: "ec2:AuthorizeSecurityGroupIngress", category: "network",
    extract: ev => { const perms = items(ev.requestParameters, "ipPermissions");
      const open = perms.some(p => items(p, "ipRanges").some(r => str(r, "cidrIp") === "0.0.0.0/0") || items(p, "ipv6Ranges").some(r => str(r, "cidrIpv6") === "::/0"));
      return [{ operation: "create", resourceType: "aws.ec2.security_group_rule", resourceId: need(ev.requestParameters, "groupId"), reversibility: "compensable",
        flags: open ? ["WORLD_OPEN_INGRESS"] as Flag[] : [] }]; } }),
  E({ eventSource: "ec2.amazonaws.com", eventName: "RevokeSecurityGroupIngress", apiAction: "ec2:RevokeSecurityGroupIngress", category: "network",
    extract: ev => [{ operation: "delete", resourceType: "aws.ec2.security_group_rule", resourceId: need(ev.requestParameters, "groupId"), reversibility: "compensable" }] }),
];
export const CATALOG_INDEX = new Map(CATALOG.map(e => [`${e.eventSource}|${e.eventName}`, e]));
