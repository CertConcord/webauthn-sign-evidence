import {createPublicKey, verify} from 'node:crypto';

const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const cosePrefix = Buffer.from('a4010103272006215820', 'hex');
const hex = value => {
  if (typeof value !== 'string' || !/^(?:[a-f0-9]{2})+$/.test(value))
    throw new TypeError('Expected nonempty lowercase octet hex');
  return Buffer.from(value, 'hex');
};

// This deliberately recognizes one synthetic Ed25519 COSE_Key shape, not general CBOR.
export function inspectSyntheticOperation(record, requiredPolicy, verifierFacts = {}) {
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
  // The recorded request is evidence, not the verifier's policy authority.
  if (requiredPolicy === null || typeof requiredPolicy !== 'object' ||
      Array.isArray(requiredPolicy))
    throw new TypeError('Verifier policy is required');
  const unmetEvidence = [];
  for (const [required, fact] of [
    ['requireAttestation', 'attestationVerified'],
    ['requireUserPresence', 'userPresenceVerified'],
    ['requireUserVerification', 'userVerificationVerified'],
    ['requireAssociatedWebAuthnResult', 'associatedWebAuthnResultVerified'],
  ]) {
    if (!Object.hasOwn(requiredPolicy, required))
      throw new TypeError(`Verifier policy requires boolean ${required}`);
    const needed = requiredPolicy[required];
    if (typeof needed !== 'boolean')
      throw new TypeError(`Verifier policy requires boolean ${required}`);
    if (needed && verifierFacts[fact] !== true)
      unmetEvidence.push(fact);
  }
  return {signatureMathValid, policySatisfied: unmetEvidence.length === 0,
    unmetEvidence};
}
