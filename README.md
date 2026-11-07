# Effect Contract MVP — Minimal Spike

First implementation slice only:
- contract types
- RFC 8785 canonicalization + SHA-256
- Ed25519 signing/verification with domain separation
- verifier checks
- fail-closed broker
- atomic single-use nonce abstraction
- A01 IAM escalation classifier
- strict JSON parsing and envelope shape validation
- Effect Catalog v0.1: CloudTrail -> effects -> classification (docs/EFFECT_CATALOG.md)
- A44 live experiment scripts (experiments/a44, run in a sandbox AWS account)

Not yet included: AWS STS, GitHub OIDC, Terraform parser, CloudTrail/EventBridge, EKS audit, persistent storage, break-glass, reconciler, A04 live test, A44 live test.

## Status
See docs/REVIEW_NOTES.md for fixes applied and open items.

## Run

```bash
npm install
npm test
npm run build
```

Use a dedicated sandbox AWS account for the live spike. Never run the scenarios against production.
