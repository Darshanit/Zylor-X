import type { ContractEnvelope, Presented } from "../contract/types.js";
import { verifyContract, type KeyResolver } from "../verifier/index.js";
export interface NonceStore { consumeOnce(nonce: string): boolean; }
/** Spike only. Production needs an atomic conditional/unique write shared by all broker instances. */
export class InMemoryNonceStore implements NonceStore {
  private used = new Set<string>();
  consumeOnce(n: string) { if (this.used.has(n)) return false; this.used.add(n); return true; }
}
export interface Credential { credentialId: string; sourceIdentity: string; issuedAt: string; expiresAt: string; permissions: string[]; }
export interface CredentialIssuer { issue(contract: ContractEnvelope): Credential; }
export interface BrokerDeps extends KeyResolver {
  nonceStore: NonceStore; credentialIssuer: CredentialIssuer;
  revokedIssuerKeyIds: ReadonlySet<string>; knownApprovers: ReadonlySet<string>;
}
export class Broker {
  constructor(private d: BrokerDeps) {}
  issue(contract: ContractEnvelope, now: Date, presented: Presented): Credential {
    let v;
    try { v = verifyContract(contract, { now, revokedIssuerKeyIds: this.d.revokedIssuerKeyIds,
            knownApprovers: this.d.knownApprovers, presented }, this.d); }
    catch { throw new Error("BROKER_DENIED:MALFORMED"); } // any verifier exception denies
    if (!v.ok) throw new Error(`BROKER_DENIED:${v.code}`);
    // Consume BEFORE issuing: concurrent duplicates lose the race instead of both getting credentials.
    if (!this.d.nonceStore.consumeOnce(contract.payload.metadata.nonce)) throw new Error("BROKER_DENIED:NONCE_REPLAY");
    return this.d.credentialIssuer.issue(contract);
  }
}
