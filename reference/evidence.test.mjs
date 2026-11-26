import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createPublicKey, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {inspectSyntheticOperation} from './evidence.mjs';

const load = path => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const record = load('../vectors/operation-evidence.json');
const direct = load('../vectors/direct-input.json');
const assertion = load('../vectors/assertion-shape.json');
const bytes = hex => Buffer.from(hex, 'hex');
const requiredPolicy = Object.freeze({
  requireAttestation: true,
  requireUserPresence: true,
  requireUserVerification: true,
  requireAssociatedWebAuthnResult: true,
});

test('synthetic operation preserves key generation and exact direct signing bytes', () => {
  assert.equal(record.selectedDraft, 'w3cSignBranch');
  assert.equal(record.keyGeneration.cosePublicKeyHex.slice(-64),
    direct.publicKeySpkiDerHex.slice(-64));
  assert.equal(record.signingOperation.tbsHex, direct.tbsHex);
  assert.equal(record.signingOperation.signatureHex, direct.signatureHex);
  assert.equal(record.keyGeneration.attestation.status, 'unavailable');
  assert.equal(record.signingOperation.associatedWebAuthnResult.status, 'unavailable');
  const result = inspectSyntheticOperation(record, requiredPolicy);
  assert.equal(result.signatureMathValid, true);
  assert.equal(result.policySatisfied, false);
});

test('a valid assertion-shaped signature cannot stand in for the direct signature', () => {
  const assertionInput = Buffer.concat([
    bytes(assertion.authenticatorDataHex),
    createHash('sha256').update(bytes(assertion.clientDataJSONHex)).digest(),
  ]);
  assert.equal(createHash('sha256').update(assertionInput).digest('hex'),
    assertion.assertionInputSha256);
  const credentialKey = createPublicKey({
    key: bytes(assertion.credentialPublicKeySpkiDerHex), format: 'der', type: 'spki',
  });
  assert.equal(verify(null, assertionInput, credentialKey,
    bytes(assertion.assertionSignatureHex)), true);
  const substituted = structuredClone(record);
  substituted.signingOperation.signatureHex = assertion.assertionSignatureHex;
  assert.equal(inspectSyntheticOperation(substituted, requiredPolicy).signatureMathValid, false);
});

test('challenge bytes cannot be substituted for the extension tbs', () => {
  assert.notEqual(assertion.challengeHex, record.signingOperation.tbsHex);
  const substituted = structuredClone(record);
  substituted.signingOperation.tbsHex = assertion.challengeHex;
  assert.equal(inspectSyntheticOperation(substituted, requiredPolicy).signatureMathValid, false);
});

test('client claims and valid signature do not repair absent policy evidence', () => {
  assert.deepEqual(record.signingOperation.clientClaims,
    {userPresence: true, userVerification: true, attested: true});
  const result = inspectSyntheticOperation(record, requiredPolicy, {
    attestationVerified: false,
    userPresenceVerified: false,
    userVerificationVerified: false,
    associatedWebAuthnResultVerified: false,
  });
  assert.equal(result.signatureMathValid, true);
  assert.equal(result.policySatisfied, false);
  assert.deepEqual(result.unmetEvidence, [
    'attestationVerified', 'userPresenceVerified',
    'userVerificationVerified', 'associatedWebAuthnResultVerified',
  ]);
});

test('recorded policy downgrade does not change verifier policy', () => {
  const downgraded = structuredClone(record);
  for (const name of Object.keys(requiredPolicy))
    downgraded.keyGeneration.requestedPolicy[name] = false;
  const baseline = inspectSyntheticOperation(record, requiredPolicy);
  assert.deepEqual(inspectSyntheticOperation(downgraded, requiredPolicy), baseline);
  assert.equal(baseline.signatureMathValid, true);
  assert.equal(baseline.policySatisfied, false);
  const restored = structuredClone(downgraded);
  restored.keyGeneration.requestedPolicy = {...requiredPolicy};
  assert.deepEqual(inspectSyntheticOperation(restored, requiredPolicy), baseline);
});

test('verifier policy must be complete and explicit', () => {
  assert.throws(() => inspectSyntheticOperation(record), /Verifier policy is required/);
  assert.throws(() => inspectSyntheticOperation(record, {}),
    /Verifier policy requires boolean requireAttestation/);
});
