import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {decodeSyntheticSignRequest, decodeSyntheticSignResponse,
  extractSyntheticSignRequestFraming} from './source-v6-cbor-boundary.mjs';

const vector = JSON.parse(readFileSync(new URL(
  '../vectors/source-v6-cbor-shrink-snapshot.json', import.meta.url), 'utf8'));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('resizing a length-tracking map during its copy cannot synthesize a tail byte', () => {
  for (const [name, encodedHex, initialSha, shrunkenHex, shrunkenSha,
    decode, output] of [
    ['sign request', vector.requestMapHex, vector.requestMapSha256,
      vector.requestAfterShrinkHex, vector.requestAfterShrinkSha256,
      decodeSyntheticSignRequest, value => value.toBeSignedBytes()],
    ['opaque args framing', vector.requestMapHex, vector.requestMapSha256,
      vector.requestAfterShrinkHex, vector.requestAfterShrinkSha256,
      extractSyntheticSignRequestFraming, value => value.toBeSignedBytes()],
    ['sign response', vector.responseMapHex, vector.responseMapSha256,
      vector.responseAfterShrinkHex, vector.responseAfterShrinkSha256,
      decodeSyntheticSignResponse, value => value.signatureBytes()],
  ]) {
    const initial = Buffer.from(encodedHex, 'hex');
    assert.equal(sha(initial), initialSha, name);
    const backing = new ArrayBuffer(initial.length, {maxByteLength: initial.length});
    const input = new Uint8Array(backing);
    input.set(initial);
    assert.equal(output(decode(input)).toString('hex'),
      vector.originalContentHex, name + ' normal control');
    const originalAlloc = Buffer.alloc;
    let resized = false;
    Buffer.alloc = function(size, ...args) {
      if (!resized && size === initial.length) {
        resized = true;
        backing.resize(initial.length - 1);
      }
      return originalAlloc.call(this, size, ...args);
    };
    try {
      assert.throws(() => decode(input), /changed during snapshot/,
        name + ' must reject a partially copied input');
    } finally {
      Buffer.alloc = originalAlloc;
    }
    assert.equal(resized, true, name + ' must hit the actual input allocator');
    assert.equal(Buffer.from(input).toString('hex'), shrunkenHex, name);
    assert.equal(sha(input), shrunkenSha, name);
  }
});

test('growth after admission retains the original fixed CBOR byte range', () => {
  for (const [name, encodedHex, decode, output] of [
    ['sign request', vector.requestMapHex,
      decodeSyntheticSignRequest, value => value.toBeSignedBytes()],
    ['opaque args framing', vector.requestMapHex,
      extractSyntheticSignRequestFraming, value => value.toBeSignedBytes()],
    ['sign response', vector.responseMapHex,
      decodeSyntheticSignResponse, value => value.signatureBytes()],
  ]) {
    const initial = Buffer.from(encodedHex, 'hex');
    const backing = new ArrayBuffer(initial.length,
      {maxByteLength: initial.length + 1});
    const input = new Uint8Array(backing);
    input.set(initial);
    const originalAlloc = Buffer.alloc;
    let grew = false;
    Buffer.alloc = function(size, ...args) {
      if (!grew && size === initial.length) {
        grew = true;
        backing.resize(initial.length + 1);
        input[input.length - 1] = 0xff;
      }
      return originalAlloc.call(this, size, ...args);
    };
    try {
      assert.equal(output(decode(input)).toString('hex'),
        vector.originalContentHex, name);
    } finally {
      Buffer.alloc = originalAlloc;
    }
    assert.equal(grew, true, name + ' must hit the actual input allocator');
    assert.equal(input.byteLength, initial.length + 1, name);
    assert.equal(input[input.length - 1], 0xff, name);
  }
});
