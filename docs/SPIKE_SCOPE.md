# Spike scope

Build only contract, signing, verifier, broker and A01 first. The broker uses an in-memory nonce store solely to demonstrate the atomic state transition; production must use a conditional/unique datastore operation across broker instances.

After these tests pass, add the sandbox AWS path: GitHub OIDC -> AWS STS, real Terraform saved plans, SourceIdentity, CloudTrail and EventBridge. Then implement A04 and A44 with a dedicated sandbox account, SCP safety boundary, throwaway ambient credentials, explicit AWS service-actor allowlists, and an empty starting account.

For A44, classify ATTEMPTED-DENIED only if the denied event has the contract SourceIdentity and the action is outside the contract effects. A denied in-contract action is a compiler/enforcement bug; a denial without the change ID is unrelated noise.
