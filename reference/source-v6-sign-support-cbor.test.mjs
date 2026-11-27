import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createPublicKey, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {decodeSyntheticSignRequest, decodeSyntheticSignResponse} from
  './source-v6-cbor-boundary.mjs';
import {decodeDraftSupportList} from './source-v6-model.mjs';
import {prepareSyntheticCompactJws} from './optional-jws.mjs';

const vector = JSON.parse(readFileSync(
  new URL('../vectors/source-v6-sign-support-cbor.json', import.meta.url), 'utf8'));
const jws = JSON.parse(readFileSync(
  new URL('../vectors/optional-jws.json', import.meta.url), 'utf8'));
const hex = value => Buffer.from(value, 'hex');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const publicKey = createPublicKey({
  key: hex(jws.publicKeySpkiDerHex), format: 'der', type: 'spki',
});

test('sign with support preserves the exact signed content and complete JWS', () => {
  const encodedRequest = hex(vector.signSupportRequestMapHex);
  const encodedResponse = hex(vector.signSupportResponseMapHex);
  assert.equal(sha256(encodedRequest), vector.signSupportRequestSha256);
  assert.equal(sha256(encodedResponse), vector.signSupportResponseSha256);
  const request = decodeSyntheticSignRequest(encodedRequest);
  const response = decodeSyntheticSignResponse(encodedResponse);
  assert.equal(request.supportRequested, true);
  assert.equal(request.keyHandleBytes().toString('hex'), 'a1b2c3d4');
  const tbs = request.toBeSignedBytes();
  const signature = response.signatureBytes();
  assert.equal(tbs.toString('ascii'), jws.signingInputAscii);
  assert.equal(signature.toString('hex'), jws.signatureHex);
  assert.equal(verify(null, tbs, publicKey, signature), true);
  assert.equal(verify(null, encodedRequest, publicKey, signature), false);
  const prepared = prepareSyntheticCompactJws(
    hex(jws.protectedHeaderUtf8Hex), hex(jws.payloadHex));
  assert.deepEqual(prepared.toBeSignedBytes(), tbs);
  assert.equal(prepared.complete(signature, hex(jws.publicKeySpkiDerHex))
    .sha256Imprint(), vector.completeCompactJwsSha256);

  const support = response.supportList();
  assert.deepEqual(support, vector.expectedSupportList);
  assert.deepEqual(decodeDraftSupportList(support).pairs, vector.expectedPairs);
});

test('omitted support on a signed response means unknown capability', () => {
  const request = decodeSyntheticSignRequest(hex(vector.signSupportRequestMapHex));
  const omitted = decodeSyntheticSignResponse(hex(vector.omittedSupportResponseMapHex));
  assert.equal(request.supportRequested, true);
  assert.equal(omitted.supportList(), null);
  assert.equal(verify(null, request.toBeSignedBytes(), publicKey,
    omitted.signatureBytes()), true);
  const ordinary = decodeSyntheticSignRequest(hex(vector.baseRequestMapHex));
  assert.equal(ordinary.supportRequested, false);
  assert.equal(ordinary.toBeSignedBytes().toString('ascii'),
    request.toBeSignedBytes().toString('ascii'));
});

test('sparse support CBOR retains index positions and a larger child algorithm', () => {
  const encoded = hex(vector.sparseSupportResponseMapHex);
  assert.equal(sha256(encoded), vector.sparseSupportResponseSha256);
  const response = decodeSyntheticSignResponse(encoded);
  assert.equal(response.signatureBytes().toString('hex'), jws.signatureHex);
  const support = response.supportList();
  assert.deepEqual(support, vector.expectedSparseSupportList);
  assert.deepEqual(decodeDraftSupportList(support).pairs,
    vector.expectedSparsePairs);
  const largeNegative = encoded.indexOf(hex('39012b'));
  assert.notEqual(largeNegative, -1);
  const overlong = Buffer.concat([
    encoded.subarray(0, largeNegative), hex('3a0000012b'),
    encoded.subarray(largeNegative + 3)]);
  assert.throws(() => decodeSyntheticSignResponse(overlong), /Noncanonical/);
});

test('false support and empty or malformed support arrays are rejected', () => {
  const falseRequest = hex(vector.falseSupportRequestMapHex);
  const emptyResponse = hex(vector.emptySupportResponseMapHex);
  assert.equal(sha256(falseRequest), vector.falseSupportRequestSha256);
  assert.equal(sha256(emptyResponse), vector.emptySupportResponseSha256);
  assert.throws(() => decodeSyntheticSignRequest(falseRequest), /must be true/);
  assert.throws(() => decodeSyntheticSignResponse(emptyResponse), /nonempty/);
  const response = hex(vector.signSupportResponseMapHex);
  const noncanonicalLength = Buffer.concat([
    response.subarray(0, response.length - 8), hex('089802822627822627')]);
  assert.throws(() => decodeSyntheticSignResponse(noncanonicalLength), /Noncanonical/);
  const trailing = Buffer.concat([response, hex('00')]);
  assert.throws(() => decodeSyntheticSignResponse(trailing), /one complete/);
  const wrongKey = Buffer.from(response);
  wrongKey[wrongKey.length - 8] = 7;
  assert.throws(() => decodeSyntheticSignResponse(wrongKey), /support map key/);
  const duplicateKey = Buffer.from(response);
  duplicateKey[duplicateKey.length - 8] = 6;
  assert.throws(() => decodeSyntheticSignResponse(duplicateKey), /support map key/);
});

test('support and signature reads remain independent of source and one another', () => {
  const requestBytes = hex(vector.signSupportRequestMapHex);
  const responseBytes = hex(vector.signSupportResponseMapHex);
  const request = decodeSyntheticSignRequest(requestBytes);
  const response = decodeSyntheticSignResponse(responseBytes);
  const firstSignature = response.signatureBytes();
  const secondSignature = response.signatureBytes();
  assert.notStrictEqual(firstSignature.buffer, secondSignature.buffer);
  assert.notStrictEqual(firstSignature.buffer, responseBytes.buffer);
  assert.equal(firstSignature.buffer.byteLength, firstSignature.byteLength);
  const firstSupport = response.supportList();
  const secondSupport = response.supportList();
  assert.notStrictEqual(firstSupport, secondSupport);
  assert.notStrictEqual(firstSupport[0], secondSupport[0]);
  firstSupport[0][0] = -999;
  requestBytes[requestBytes.length - 3] ^= 1;
  responseBytes[responseBytes.length - 1] ^= 1;
  firstSignature[0] ^= 1;
  assert.deepEqual(response.supportList(), vector.expectedSupportList);
  assert.equal(response.signatureBytes().toString('hex'), jws.signatureHex);
  assert.equal(request.toBeSignedBytes().toString('ascii'), jws.signingInputAscii);
});
