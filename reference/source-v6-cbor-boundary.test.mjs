import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createPublicKey, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {prepareSyntheticCompactJws} from './optional-jws.mjs';
import {decodeSyntheticSignRequest, decodeSyntheticSignResponse} from
  './source-v6-cbor-boundary.mjs';

const vector = JSON.parse(readFileSync(
  new URL('../vectors/source-v6-cbor-boundary.json', import.meta.url), 'utf8'));
const jws = JSON.parse(readFileSync(
  new URL('../vectors/optional-jws.json', import.meta.url), 'utf8'));
const hex = value => Buffer.from(value, 'hex');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const publicKey = createPublicKey({
  key: hex(jws.publicKeySpkiDerHex), format: 'der', type: 'spki',
});

test('both pinned drafts literal CBOR example selects bstr content, not its header', () => {
  assert.equal(vector.sourceExampleInputHex, 'a202400643616263');
  const decoded = decodeSyntheticSignRequest(hex(vector.sourceExampleInputHex));
  assert.equal(decoded.keyHandleBytes().length, 0);
  assert.equal(decoded.encodedTbsFieldBytes().toString('hex'), '43616263');
  assert.equal(decoded.toBeSignedBytes().toString('hex'),
    vector.sourceExampleTbsContentHex);
});

test('synthetic CBOR request and response bridge exact signing input to complete JWS', () => {
  const request = decodeSyntheticSignRequest(hex(vector.syntheticJwsBridge.requestMapHex));
  const response = decodeSyntheticSignResponse(hex(vector.syntheticJwsBridge.responseMapHex));
  const tbs = request.toBeSignedBytes();
  const signature = response.signatureBytes();
  assert.equal(request.keyHandleBytes().toString('hex'),
    vector.syntheticJwsBridge.keyHandleHex);
  assert.equal(tbs.toString('ascii'), jws.signingInputAscii);
  assert.equal(sha256(tbs), vector.syntheticJwsBridge.tbsContentSha256);
  assert.equal(signature.toString('hex'), jws.signatureHex);
  assert.equal(verify(null, tbs, publicKey, signature), true);
  const prepared = prepareSyntheticCompactJws(
    hex(jws.protectedHeaderUtf8Hex), hex(jws.payloadHex));
  assert.deepEqual(prepared.toBeSignedBytes(), tbs);
  const completed = prepared.complete(signature, hex(jws.publicKeySpkiDerHex));
  assert.equal(completed.serializedBytes().toString('ascii'), jws.compactAscii);
  assert.equal(completed.sha256Imprint(),
    vector.syntheticJwsBridge.completeCompactJwsSha256);
  assert.notEqual(sha256(tbs), completed.sha256Imprint());
});

test('CBOR header, full map, digest and a changed content byte are not signed inputs', () => {
  const encoded = hex(vector.syntheticJwsBridge.requestMapHex);
  const original = Buffer.from(encoded);
  const request = decodeSyntheticSignRequest(encoded);
  const signature = decodeSyntheticSignResponse(
    hex(vector.syntheticJwsBridge.responseMapHex)).signatureBytes();
  const tbs = request.toBeSignedBytes();
  assert.equal(verify(null, request.encodedTbsFieldBytes(), publicKey, signature), false);
  assert.equal(verify(null, encoded, publicKey, signature), false);
  assert.equal(verify(null, createHash('sha256').update(tbs).digest(),
    publicKey, signature), false);
  encoded[encoded.length - 1] ^= 1;
  assert.equal(verify(null, decodeSyntheticSignRequest(encoded).toBeSignedBytes(),
    publicKey, signature), false);
  encoded[encoded.length - 1] ^= 1;
  assert.deepEqual(encoded, original);
  assert.equal(verify(null, decodeSyntheticSignRequest(encoded).toBeSignedBytes(),
    publicKey, signature), true);
});

test('changed output signature fails JWS completion; restoring exact bytes recovers it', () => {
  const encoded = hex(vector.syntheticJwsBridge.responseMapHex);
  const original = Buffer.from(encoded);
  const prepared = prepareSyntheticCompactJws(
    hex(jws.protectedHeaderUtf8Hex), hex(jws.payloadHex));
  encoded[encoded.length - 1] ^= 1;
  const altered = decodeSyntheticSignResponse(encoded).signatureBytes();
  assert.throws(() => prepared.complete(altered, hex(jws.publicKeySpkiDerHex)),
    /does not verify/);
  encoded[encoded.length - 1] ^= 1;
  assert.deepEqual(encoded, original);
  assert.equal(prepared.complete(decodeSyntheticSignResponse(encoded).signatureBytes(),
    hex(jws.publicKeySpkiDerHex)).sha256Imprint(), jws.compactSha256);
});

test('narrow CBOR boundary rejects alternate framing and returned-byte mutation', () => {
  for (const malformed of [
    'a20240065803616263', // noncanonical length for three content bytes
    'a2024006436162',     // truncated content
    'a202400543616263',   // wrong tbs map key
    'a20240064361626300', // trailing byte
  ]) assert.throws(() => decodeSyntheticSignRequest(hex(malformed)), TypeError);
  assert.throws(() => decodeSyntheticSignResponse(hex('a1034000')), TypeError);
  const decoded = decodeSyntheticSignRequest(hex(vector.syntheticJwsBridge.requestMapHex));
  const copy = decoded.toBeSignedBytes();
  copy[0] ^= 1;
  assert.equal(decoded.toBeSignedBytes().toString('ascii'), jws.signingInputAscii);
});

test('private decoded fields and every returned byte view have separate backing stores', () => {
  const requestInput = hex(vector.syntheticJwsBridge.requestMapHex);
  const responseInput = hex(vector.syntheticJwsBridge.responseMapHex);
  const request = decodeSyntheticSignRequest(requestInput);
  const response = decodeSyntheticSignResponse(responseInput);
  const accessors = [
    [() => request.keyHandleBytes(), requestInput],
    [() => request.toBeSignedBytes(), requestInput],
    [() => request.encodedTbsFieldBytes(), requestInput],
    [() => response.signatureBytes(), responseInput],
  ];
  const returned = [];
  for (const [read, source] of accessors) {
    const first = read();
    const second = read();
    assert.notStrictEqual(first.buffer, second.buffer);
    assert.notStrictEqual(first.buffer, source.buffer);
    assert.notStrictEqual(second.buffer, source.buffer);
    assert.equal(first.buffer.byteLength, first.byteLength);
    assert.equal(second.buffer.byteLength, second.byteLength);
    returned.push(first, second);
  }
  assert.equal(new Set(returned.map(value => value.buffer)).size, returned.length);
  requestInput[requestInput.length - 1] ^= 1;
  responseInput[responseInput.length - 1] ^= 1;
  for (const value of returned) value[0] ^= 1;
  assert.equal(request.toBeSignedBytes().toString('ascii'), jws.signingInputAscii);
  assert.equal(request.keyHandleBytes().toString('hex'),
    vector.syntheticJwsBridge.keyHandleHex);
  assert.equal(response.signatureBytes().toString('hex'), jws.signatureHex);
});

test('canonical two-byte bstr length preserves 256 content octets', () => {
  const content = Buffer.alloc(256, 0xa5);
  const encoded = Buffer.concat([hex('a2024006590100'), content]);
  const decoded = decodeSyntheticSignRequest(encoded);
  assert.deepEqual(decoded.toBeSignedBytes(), content);
  assert.deepEqual(decoded.encodedTbsFieldBytes(),
    Buffer.concat([hex('590100'), content]));
  assert.throws(() => decodeSyntheticSignRequest(Buffer.concat([
    hex('a20240065900ff'), content.subarray(0, 255),
  ])), /Noncanonical/);
});
