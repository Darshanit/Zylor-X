# A44 live experiment: does a denied call keep SourceIdentity in CloudTrail?

**Use a dedicated, empty sandbox AWS account** with a budget alarm. Never run this in a shared or production account.
Needs: AWS CLI v2, jq, and admin credentials for the sandbox account in your shell.

## Question
When a role session carrying `SourceIdentity=CHG-...` makes an API call that is denied by its session policy,
does the CloudTrail event record `userIdentity.sessionContext.sourceIdentity`?
This decides whether ATTEMPTED-DENIED (denied + matching change ID + out-of-contract action) can work as designed.

## Why the test role is allowed to call iam:CreateRole
The role's own policy permits `iam:CreateRole` on `effect-spike-*` names only. The session policy then allows
only `s3:ListAllMyBuckets`. A denial therefore proves the *session policy* (your compiled contract) caused it,
not a missing role permission. The name restriction caps damage if the session policy were ever ignored.

## One-time setup (replace ACCOUNT and YOU)
1. Find your caller ARN: `aws sts get-caller-identity` (use the IAM user/role ARN, not the assumed-role session ARN if you can).
2. Create `trust.json`:
```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"AWS":"arn:aws:iam::ACCOUNT:user/YOU"},
  "Action":["sts:AssumeRole","sts:SetSourceIdentity"]}]}
```
   `sts:SetSourceIdentity` must be allowed in the trust policy or AssumeRole with `--source-identity` fails.
3. Create `perms.json`:
```json
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"},
 {"Effect":"Allow","Action":"iam:CreateRole","Resource":"arn:aws:iam::ACCOUNT:role/effect-spike-*"}]}
```
4. Create the role:
```bash
aws iam create-role --role-name effect-spike-broker-role --assume-role-policy-document file://trust.json
aws iam put-role-policy --role-name effect-spike-broker-role --policy-name spike --policy-document file://perms.json
```
5. Export:
```bash
export SANDBOX_ACCOUNT_ID=ACCOUNT
export SPIKE_ROLE_ARN=arn:aws:iam::ACCOUNT:role/effect-spike-broker-role
```
## Run
`./experiments/a44/run.sh` then record the printed summary in `RESULTS.md` (template below).

## Cleanup
```bash
aws iam delete-role-policy --role-name effect-spike-broker-role --policy-name spike
aws iam delete-role --role-name effect-spike-broker-role
```
If a run ever *succeeds* in creating an `effect-spike-*` role, that is itself a failed test: delete it and investigate.

## RESULTS.md template
| Item | Value |
|---|---|
| Date / region of event | |
| Denied call recorded in CloudTrail? | |
| errorCode / errorMessage | |
| `userIdentity.sessionContext.sourceIdentity` present on the denied event? | |
| Same field present on the allowed call (`ListBuckets`)? | |
| Seconds from call to visibility in event history | |
| Event `userIdentity.arn` format | |
| Anything unexpected | |
