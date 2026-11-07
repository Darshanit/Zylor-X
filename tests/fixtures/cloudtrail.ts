// SYNTHETIC fixtures modelled on documented CloudTrail record structure. Replace with real sandbox events (see docs/EFFECT_CATALOG.md).
import type { CloudTrailEvent } from "../../src/catalog/types.js";
export const ACCT = "111111111111";
export function ev(eventSource: string, eventName: string, o: Partial<CloudTrailEvent> & { si?: string | null } = {}): CloudTrailEvent {
  const { si, ...rest } = o;
  const sourceIdentity = si === undefined ? "CHG-1" : si; // default: brokered session for CHG-1
  return { eventID: `${eventName}-id`, eventTime: "2026-09-30T12:00:00Z", eventSource, eventName, awsRegion: "ap-south-1",
    recipientAccountId: ACCT, readOnly: false,
    userIdentity: { type: "AssumedRole", arn: `arn:aws:sts::${ACCT}:assumed-role/deployer/spike-CHG-1`, accountId: ACCT,
      ...(sourceIdentity ? { sessionContext: { sourceIdentity } } : {}) },
    requestParameters: {}, responseElements: null, ...rest };
}
const iam = (n: string, rp: unknown, o: Partial<CloudTrailEvent> & { si?: string | null } = {}) => ev("iam.amazonaws.com", n, { awsRegion: "us-east-1", requestParameters: rp, ...o });
const s3 = (n: string, rp: unknown, o: Partial<CloudTrailEvent> & { si?: string | null } = {}) => ev("s3.amazonaws.com", n, { requestParameters: rp, ...o });
const ec2 = (n: string, rp: unknown, o: Partial<CloudTrailEvent> & { si?: string | null } = {}) => ev("ec2.amazonaws.com", n, { requestParameters: rp, ...o });
const ADMIN_DOC = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] });
const TRUST_ANY = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "*" }, Action: "sts:AssumeRole" }] });
export const F = {
  createRole: (o = {}) => iam("CreateRole", { roleName: "evil", assumeRolePolicyDocument: TRUST_ANY }, o),
  attachAdmin: (o = {}) => iam("AttachRolePolicy", { roleName: "evil", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }, o),
  putRolePolicy: (o = {}) => iam("PutRolePolicy", { roleName: "r1", policyName: "p1", policyDocument: ADMIN_DOC }, o),
  updateTrust: (o = {}) => iam("UpdateAssumeRolePolicy", { roleName: "r1", policyDocument: TRUST_ANY }, o),
  createPolicyVersion: (o = {}) => iam("CreatePolicyVersion", { policyArn: `arn:aws:iam::${ACCT}:policy/p1`, policyDocument: ADMIN_DOC, setAsDefault: true }, o),
  createBucket: (o = {}) => s3("CreateBucket", { bucketName: "app-bucket" }, o),
  putBucketPolicyPublic: (o = {}) => s3("PutBucketPolicy", { bucketName: "app-bucket", bucketPolicy: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::app-bucket/*" }] } }, o),
  putPab: (cfg: Record<string, boolean>, o = {}) => s3("PutPublicAccessBlock", { bucketName: "app-bucket", PublicAccessBlockConfiguration: cfg }, o),
  putVersioning: (status: string, o = {}) => s3("PutBucketVersioning", { bucketName: "app-bucket", VersioningConfiguration: { Status: status } }, o),
  deleteBucket: (o = {}) => s3("DeleteBucket", { bucketName: "app-bucket" }, o),
  runInstances: (ids: string[], o = {}) => ec2("RunInstances", { instanceType: "p4d.24xlarge" }, { responseElements: ids.length ? { instancesSet: { items: ids.map(instanceId => ({ instanceId })) } } : null, ...o }),
  terminate: (ids: string[], o = {}) => ec2("TerminateInstances", { instancesSet: { items: ids.map(instanceId => ({ instanceId })) } }, o),
  createSg: (o = {}) => ec2("CreateSecurityGroup", { groupName: "web", vpcId: "vpc-1" }, { responseElements: { groupId: "sg-1" }, ...o }),
  openIngress: (o = {}) => ec2("AuthorizeSecurityGroupIngress", { groupId: "sg-1", ipPermissions: { items: [{ ipProtocol: "tcp", fromPort: 22, toPort: 22, ipRanges: { items: [{ cidrIp: "0.0.0.0/0" }] } }] } }, o),
  closedIngress: (o = {}) => ec2("AuthorizeSecurityGroupIngress", { groupId: "sg-1", ipPermissions: { items: [{ ipProtocol: "tcp", fromPort: 443, toPort: 443, ipRanges: { items: [{ cidrIp: "10.0.0.0/8" }] } }] } }, o),
  revokeIngress: (o = {}) => ec2("AuthorizeSecurityGroupIngress".replace("Authorize", "Revoke"), { groupId: "sg-1" }, o),
};
