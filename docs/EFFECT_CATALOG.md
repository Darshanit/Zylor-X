# Effect Catalog v0.1

Turns raw CloudTrail records into effects in the **same vocabulary as contract effects**
(`create | update | delete`, provider-native resource types and ids), then classifies each against the active contract.

```
CloudTrail event -> normalizeEvent -> Observation{ outcome, effects[], mapped }
                 -> classifyObservation(contracts) -> EXPECTED | UNATTESTED | ORPHAN | ATTEMPTED-DENIED
                                                      | UNRELATED-DENIAL | BUG-DENIED-IN-CONTRACT
                                                      | TRUSTED-SERVICE | READ | NO-EFFECT
```

## Mappings (15)
| Service | API -> effect (operation, resourceType, resourceId) |
|---|---|
| IAM (global) | CreateRole -> create aws.iam.role, name; AttachRolePolicy -> create aws.iam.role_policy_attachment, `role/policyArn`; PutRolePolicy -> update aws.iam.role_policy, `role:policy`; UpdateAssumeRolePolicy -> update aws.iam.role; CreatePolicyVersion -> update aws.iam.policy, ARN |
| S3 | CreateBucket; PutBucketPolicy; PutPublicAccessBlock; PutBucketVersioning; DeleteBucket (destructive, irreversible) |
| EC2 | RunInstances (one effect per instance id, `UNRESOLVED` if denied); TerminateInstances (per id, destructive); CreateSecurityGroup; AuthorizeSecurityGroupIngress; RevokeSecurityGroupIngress |

Resource ids follow the provider-native id Terraform uses, so plan-derived contracts compare directly.

## Classification rules (summary)
- Read-only and unmapped: `READ`. **Unmapped mutating APIs are never dropped**: they classify as `UNATTESTED` (brokered) or `ORPHAN` with reason `UNMAPPED_API`.
- Non-denial errors (for example EntityAlreadyExists): `NO-EFFECT`.
- Denied: needs matching SourceIdentity and an active contract, else `UNRELATED-DENIAL`. Out of contract: `ATTEMPTED-DENIED`. In contract: `BUG-DENIED-IN-CONTRACT`.
- Succeeded: no SourceIdentity: `ORPHAN` (or `TRUSTED-SERVICE` if allowlisted). Unknown or inactive change id: `ORPHAN`.
- Violations that make a brokered success `UNATTESTED`: `NOT_IN_CONTRACT`, `FORBIDDEN_OPERATION`, `IAM_NOT_ALLOWED`, `DESTRUCTIVE_NOT_ALLOWED`, `WRONG_ACCOUNT`, `REGION_NOT_ALLOWED`, `UNMAPPED_API`, `NORMALIZATION_ERROR`.
- Global services (IAM) are exempt from the region check because they log in us-east-1.
- Flags (informational): `PRIVILEGE_ESCALATION`, `WILDCARD_PRINCIPAL`, `TRUST_POLICY_CHANGE`, `PUBLIC_EXPOSURE`, `RECOVERY_WEAKENED`, `WORLD_OPEN_INGRESS`, `SENSITIVE_IAM`, `UNPARSED_POLICY`.
- IAM stays in the catalog although the MVP contract scope is "no IAM effects": observing IAM activity is what lets the system flag it.

## Known limits (v0.1)
1. **Fixtures are synthetic.** They follow CloudTrail's documented structure from memory of the format, not from your account. Field shapes (for example EC2 `items` lists, S3 `bucketPolicy` as an object, IAM policy documents as strings, the EC2 denial code `Client.UnauthorizedOperation`) must be confirmed against real events. Put real events in `tests/fixtures/real/`.
2. No implied-effect modelling yet (controller children, service-linked roles). No resource-count budget (`maxResourcesAffected`) because that needs aggregation across events.
3. Matching is exact or trailing-`*` glob on resource id; `UNRESOLVED` ids match on operation and type only (deliberately loose for denied creates).
4. Event-history lookups and S3 delivery are not modelled; latency is measured separately in the A44 spike.
5. Only management events. S3 object-level and similar data events are out of scope.

## Adding a mapping
Add a `CatalogEntry` in `src/catalog/entries.ts` (eventSource, eventName, apiAction, category, `extract`), add a synthetic fixture in `tests/fixtures/cloudtrail.ts`, add a row to the table test, and, when possible, a real event under `tests/fixtures/real/`.
