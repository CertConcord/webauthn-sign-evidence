import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {types} from 'node:util';
import {decodeSyntheticSignRequest, decodeSyntheticSignResponse,
        extractSyntheticSignRequestFraming} from './source-v6-cbor-boundary.mjs';

const vector = JSON.parse(readFileSync(
  new URL('../vectors/source-v6-cbor-precopy.json', import.meta.url), 'utf8'));
const sha256 = value => createHash('sha256').update(value).digest('hex');

test('synthetic CBOR entries reject impossible map sizes before a full copy', () => {
  const invalid = Buffer.alloc(vector.overLimitBytes,
    Number.parseInt(vector.overLimitFillHex, 16));
  assert.equal(sha256(invalid), vector.overLimitSha256);
  Object.defineProperty(invalid, 'byteLength', {value: 0});
  Object.defineProperty(invalid, 'length', {value: 0});
  const NativeUint8Array = globalThis.Uint8Array;
  let attemptedCopy = false;
  globalThis.Uint8Array = class extends NativeUint8Array {
    constructor(value, ...args) {
      if (types.isUint8Array(value) && value === invalid) {
        attemptedCopy = true;
        throw new Error('full copy before size rejection');
      }
      super(value, ...args);
    }
  };
  try {
    for (const decode of [decodeSyntheticSignRequest,
                          extractSyntheticSignRequestFraming,
                          decodeSyntheticSignResponse]) {
      assert.throws(() => decode(invalid), /synthetic CBOR map exceeds local limit/);
      assert.equal(attemptedCopy, false);
    }
  } finally {
    globalThis.Uint8Array = NativeUint8Array;
  }
});

test('largest supported request map remains available at its exact boundary', () => {
  const field = Buffer.alloc(vector.fieldContentBytes,
    Number.parseInt(vector.fieldFillHex, 16));
  const segments = vector.maxRequestSegmentsHex.map(value => Buffer.from(value, 'hex'));
  const encoded = Buffer.concat([
    segments[0], field, segments[1], field,
    segments[2], field, segments[3],
  ]);
  assert.equal(encoded.length, vector.maxRequestBytes);
  assert.equal(sha256(encoded), vector.maxRequestSha256);
  const decoded = extractSyntheticSignRequestFraming(encoded);
  assert.equal(decoded.keyHandleBytes().length, vector.fieldContentBytes);
  assert.equal(decoded.toBeSignedBytes().length, vector.fieldContentBytes);
  assert.equal(decoded.argsContentBytes().length, vector.fieldContentBytes);
  assert.equal(decoded.supportRequested, true);
  assert.throws(() => decodeSyntheticSignRequest(encoded), TypeError);
});
