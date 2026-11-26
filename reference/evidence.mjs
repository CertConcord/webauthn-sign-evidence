import {createPublicKey, verify} from 'node:crypto';

const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const cosePrefix = Buffer.from('a4010103272006215820', 'hex');
const hex = value => {
  if (typeof value !== 'string' || !/^(?:[a-f0-9]{2})+$/.test(value))
    throw new TypeError('Expected nonempty lowercase octet hex');
  return Buffer.from(value, 'hex');
};

// This deliberately recognizes one synthetic Ed25519 COSE_Key shape, not general CBOR.
export function inspectSyntheticOperation(record, verifierFacts = {}) {
  const generation = record.keyGeneration;
  const operation = record.signingOperation;
  if (generation.signingAlgorithm !== 'Ed25519')
    throw new TypeError('Only the synthetic Ed25519 fixture is selected');
  const coseKey = hex(generation.cosePublicKeyHex);
  if (coseKey.length !== cosePrefix.length + 32 ||
      !coseKey.subarray(0, cosePrefix.length).equals(cosePrefix))
    throw new TypeError('Unexpected synthetic COSE_Key shape');
  const key = createPublicKey({
    key: Buffer.concat([spkiPrefix, coseKey.subarray(cosePrefix.length)]),
    format: 'der', type: 'spki',
  });
  const signatureMathValid = verify(null, hex(operation.tbsHex), key,
    hex(operation.signatureHex));
  const policy = generation.requestedPolicy;
  const unmetEvidence = [];
  for (const [required, fact] of [
    ['requireAttestation', 'attestationVerified'],
    ['requireUserPresence', 'userPresenceVerified'],
    ['requireUserVerification', 'userVerificationVerified'],
    ['requireAssociatedWebAuthnResult', 'associatedWebAuthnResultVerified'],
  ]) {
    if (policy[required] && verifierFacts[fact] !== true) unmetEvidence.push(fact);
  }
  return {signatureMathValid, policySatisfied: unmetEvidence.length === 0,
    unmetEvidence};
}
