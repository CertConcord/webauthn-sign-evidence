import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {prepareSyntheticCompactJws} from './optional-jws.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/optional-jws.json', import.meta.url)));
const bytes = hex => Buffer.from(hex, 'hex');
const hash = value => createHash('sha256').update(value).digest('hex');
const seed = createHash('sha256').update(vector.keySeedLabel, 'utf8').digest();
const privateKey = createPrivateKey({
  key: Buffer.concat([bytes('302e020100300506032b657004220420'), seed]),
  format: 'der', type: 'pkcs8',
});
const publicKeyDer = createPublicKey(privateKey).export({format: 'der', type: 'spki'});
const header = bytes(vector.protectedHeaderUtf8Hex);
const payload = bytes(vector.payloadHex);
const prepared = prepareSyntheticCompactJws(header, payload);
const signature = bytes(vector.signatureHex);
const completed = prepared.complete(signature, publicKeyDer);

function shortDerTlv(source, offset) {
  const tag = source[offset];
  const length = source[offset + 1];
  assert.ok(length < 128, 'this fixture uses short-form DER lengths');
  const end = offset + 2 + length;
  assert.ok(end <= source.length);
  return {tag, value: source.subarray(offset + 2, end), end};
}

test('exact signing input precedes signature and complete byte imprint', () => {
  assert.equal(publicKeyDer.toString('hex'), vector.publicKeySpkiDerHex);
  assert.equal(prepared.toBeSignedBytes().toString('ascii'), vector.signingInputAscii);
  assert.deepEqual(sign(null, prepared.toBeSignedBytes(), privateKey), signature);
  assert.equal(completed.serializedBytes().toString('ascii'), vector.compactAscii);
  assert.equal(completed.sha256Imprint(), vector.compactSha256);
  assert.notEqual(hash(prepared.toBeSignedBytes()), vector.compactSha256);
  assert.equal(verify(null, prepared.toBeSignedBytes(), createPublicKey({
    key: publicKeyDer, format: 'der', type: 'spki',
  }), signature), true);
});

test('offline RFC 3161 request carries SHA-256 of the complete frozen bytes', () => {
  const der = bytes(vector.timestampRequestDerHex);
  const request = shortDerTlv(der, 0);
  assert.equal(request.tag, 0x30);
  assert.equal(request.end, der.length);
  const version = shortDerTlv(request.value, 0);
  assert.equal(version.tag, 0x02);
  assert.deepEqual(version.value, bytes('01'));
  const imprint = shortDerTlv(request.value, version.end);
  assert.equal(imprint.tag, 0x30);
  const algorithm = shortDerTlv(imprint.value, 0);
  assert.equal(algorithm.tag, 0x30);
  const oid = shortDerTlv(algorithm.value, 0);
  assert.equal(oid.tag, 0x06);
  assert.deepEqual(oid.value, bytes('608648016503040201'));
  const nullParameters = shortDerTlv(algorithm.value, oid.end);
  assert.equal(nullParameters.tag, 0x05);
  assert.equal(nullParameters.value.length, 0);
  assert.equal(nullParameters.end, algorithm.value.length);
  const digest = shortDerTlv(imprint.value, algorithm.end);
  assert.equal(digest.tag, 0x04);
  assert.equal(digest.value.length, 32);
  assert.equal(digest.end, imprint.value.length);
  assert.deepEqual(digest.value, createHash('sha256').update(completed.serializedBytes()).digest());
  assert.notDeepEqual(digest.value, createHash('sha256').update(prepared.toBeSignedBytes()).digest());
  const certRequested = shortDerTlv(request.value, imprint.end);
  assert.equal(certRequested.tag, 0x01);
  assert.deepEqual(certRequested.value, bytes('ff'));
  assert.equal(certRequested.end, request.value.length); // no nonce or other fields
});

test('caller mutation of returned bytes cannot change the completed artifact', () => {
  const inputCopy = prepared.toBeSignedBytes();
  inputCopy[0] ^= 1;
  const completedCopy = completed.serializedBytes();
  completedCopy[0] ^= 1;
  assert.equal(prepared.toBeSignedBytes().toString('ascii'), vector.signingInputAscii);
  assert.equal(completed.serializedBytes().toString('ascii'), vector.compactAscii);
  assert.equal(completed.sha256Imprint(), vector.compactSha256);
});

test('single changed signature byte fails verification and imprint; restoration recovers both', () => {
  const original = completed.serializedBytes();
  const altered = Buffer.from(original);
  const firstSignatureOffset = altered.lastIndexOf(46) + 1;
  const originalByte = altered[firstSignatureOffset];
  altered[firstSignatureOffset] = originalByte === 65 ? 66 : 65;
  const changedSignature = Buffer.from(altered.toString('ascii').split('.')[2], 'base64url');
  assert.equal(verify(null, prepared.toBeSignedBytes(), createPublicKey({
    key: publicKeyDer, format: 'der', type: 'spki',
  }), changedSignature), false);
  assert.notEqual(hash(altered), vector.compactSha256);
  assert.equal(hash(prepared.toBeSignedBytes()), hash(original.subarray(0, firstSignatureOffset - 1)));
  altered[firstSignatureOffset] = originalByte;
  assert.deepEqual(altered, original);
  assert.equal(hash(altered), vector.compactSha256);
  assert.equal(verify(null, prepared.toBeSignedBytes(), createPublicKey({
    key: publicKeyDer, format: 'der', type: 'spki',
  }), signature), true);
});

test('reserializing equivalent header requires a new signature and changes timestamp target', () => {
  const alternative = prepareSyntheticCompactJws(bytes(vector.reserializedHeaderUtf8Hex), payload);
  assert.deepEqual(JSON.parse(header.toString('utf8')),
    JSON.parse(bytes(vector.reserializedHeaderUtf8Hex).toString('utf8')));
  assert.equal(alternative.toBeSignedBytes().toString('ascii'), vector.reserializedSigningInputAscii);
  assert.throws(() => alternative.complete(signature, publicKeyDer), /does not verify/);
  const alternativeSignature = sign(null, alternative.toBeSignedBytes(), privateKey);
  assert.equal(alternativeSignature.toString('hex'), vector.reserializedSignatureHex);
  const reserialized = alternative.complete(alternativeSignature, publicKeyDer);
  assert.equal(reserialized.serializedBytes().toString('ascii'), vector.reserializedCompactAscii);
  assert.equal(reserialized.sha256Imprint(), vector.reserializedCompactSha256);
  assert.notEqual(reserialized.sha256Imprint(), completed.sha256Imprint());
});

test('JSON whitespace retains its exact signed header bytes', () => {
  const validHeader = bytes(vector.jsonWhitespaceHeaderUtf8Hex);
  assert.deepEqual(JSON.parse(validHeader.toString('utf8')), JSON.parse(header.toString('utf8')));
  const option = prepareSyntheticCompactJws(validHeader, payload);
  assert.equal(option.toBeSignedBytes().toString('ascii'), vector.jsonWhitespaceSigningInputAscii);
  const validSignature = sign(null, option.toBeSignedBytes(), privateKey);
  assert.equal(validSignature.toString('hex'), vector.jsonWhitespaceSignatureHex);
  const artifact = option.complete(validSignature, publicKeyDer);
  assert.equal(artifact.serializedBytes().toString('ascii'), vector.jsonWhitespaceCompactAscii);
  assert.equal(artifact.sha256Imprint(), vector.jsonWhitespaceCompactSha256);
  assert.notEqual(artifact.sha256Imprint(), completed.sha256Imprint());
});

test('non-JSON whitespace cannot pass the protected header check', () => {
  for (const invalidHex of [vector.formFeedHeaderUtf8Hex,
                            vector.nonBreakingSpaceHeaderUtf8Hex]) {
    const invalidHeader = bytes(invalidHex);
    assert.throws(() => JSON.parse(invalidHeader.toString('utf8')), SyntaxError);
    assert.throws(() => prepareSyntheticCompactJws(invalidHeader, payload),
      /requires a protected EdDSA header/);
  }
});

test('changed payload and malformed or unselected header cannot reuse the signature', () => {
  const changedPayload = Buffer.from(payload);
  changedPayload[0] ^= 1;
  assert.throws(() => prepareSyntheticCompactJws(header, changedPayload)
    .complete(signature, publicKeyDer), /does not verify/);
  assert.throws(() => prepareSyntheticCompactJws(Buffer.from('{"alg":"none"}'), payload),
    /requires a protected EdDSA header/);
  assert.throws(() => prepareSyntheticCompactJws(Buffer.from('{"alg":"EdDSA","crit":["x"]}'), payload),
    /requires a protected EdDSA header/);
  assert.throws(() => prepareSyntheticCompactJws(Buffer.concat([bytes('efbbbf'), header]), payload),
    /requires a protected EdDSA header/);
});

test('outer time and log fields do not change the frozen first imprint', () => {
  const first = {artifact: completed.serializedBytes().toString('ascii'),
    timestampResponse: null, logProof: null};
  const later = {...first, timestampResponse: 'synthetic-only', logProof: 'synthetic-only'};
  assert.notEqual(hash(Buffer.from(JSON.stringify(first))),
    hash(Buffer.from(JSON.stringify(later))));
  assert.equal(hash(Buffer.from(later.artifact, 'ascii')), completed.sha256Imprint());
  assert.equal(later.timestampResponse === 'synthetic-only', true);
});
