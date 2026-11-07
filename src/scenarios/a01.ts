import type {ContractEnvelope,Effect} from "../contract/types.js";
export type A01Decision="ALLOW"|"ATTEMPTED-DENIED"|"BUG-DENIED-IN-CONTRACT"|"UNRELATED-DENIAL";
function matches(es:Effect[],r:{action:string;resourceType:string;resourceId:string}){return es.some(e=>e.operation===r.action&&e.resourceType===r.resourceType&&e.resourceId===r.resourceId);}
export function classifyDeniedA01(c:ContractEnvelope,r:{action:string;resourceType:string;resourceId:string;sourceIdentity?:string}):A01Decision{
 if(!r.sourceIdentity||r.sourceIdentity!==c.payload.authorization.sourceIdentity)return "UNRELATED-DENIAL";
 return matches(c.payload.effects,r)?"BUG-DENIED-IN-CONTRACT":"ATTEMPTED-DENIED";
}
export function evaluateA01(c:ContractEnvelope,r:{action:string;resourceType:string;resourceId:string;sourceIdentity?:string}):A01Decision{return matches(c.payload.effects,r)?"ALLOW":classifyDeniedA01(c,r);}
