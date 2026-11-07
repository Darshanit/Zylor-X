# Review notes (rev 1)

## Fixed in this revision
| ID | Issue | Fix |
|----|-------|-----|
| B1 | `npm run build` failed (canonicalize typing, exactOptionalPropertyTypes) | Cast import; widen context types |
| B2 | Separation-of-duties test could never reach its check | Test rebuilt with requiredApprover == sponsor |
| F1 | Omitting the presented plan hash skipped plan binding (fail-open) | PLAN_MISSING, fail closed |
| F2 | Omitting the presented state skipped state binding | STATE_MISSING, fail closed |
| F3 | Envelope issuer key id was never compared to payload `issuer.keyId` | ISSUER_KEY_MISMATCH; revocation checked on the signed key id |
| F4 | Resolver could not bind an approver key to a principal | `getApproverPublicKey(principal, keyId)` must return a key only for its owner |
| F5 | Invalid `expiresAt` parsed to NaN, so the expiry check passed | INVALID_TIMESTAMP / NOT_YET_VALID; explicit clock skew |

## Rev 2: closed
| Item | Change |
|------|--------|
| Strict JSON | `src/parse`: duplicate keys, `__proto__`, lone surrogates, decimals/exponents, unsafe integers, -0, trailing data and deep nesting are rejected; envelope shape is validated before verification. |
| v0.2 alignment | Field names, `example.invalid/v0.2/{approval,issuance}` contexts, `sha256:` hash format and the signature envelope (`approval.signer/keyId/signature`, `issuer.keyId/signature`) now match the spec. Signed bytes are `UTF-8(context + "\n" + contractHash)`. |
| Account/region | `presented.target` is required and must equal `payload.target`; `allowedRegions` is enforced; fails closed. |
| actor.owner | Separation of duties compares the approver to `sponsor.principal` and `actor.owner`. |
| Hardening | Verifier exceptions deny; `standing-template` approvals are rejected until implemented. |

## Still open
1. Run the A44 live experiment (`experiments/a44/`) and record `RESULTS.md`. Everything downstream depends on it.
2. Effect catalog v0.1 exists (15 mappings, synthetic fixtures). Replace fixtures with real events; extend the catalog from observed Terraform plans.
3. Scope nonce keys by issuer, retain until expiry, and use an atomic conditional write across broker instances.
4. Real key registries (KMS, IdP) instead of test resolvers; approver key rotation and revocation.
5. Standing-template approval verification.
6. `classifyDeniedA01` matches effect-level strings; live events are API calls (item 2).
