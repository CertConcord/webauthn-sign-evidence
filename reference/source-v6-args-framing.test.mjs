import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {decodeSyntheticSignRequest, extractSyntheticSignRequestFraming} from
  './source-v6-cbor-boundary.mjs';

const vector = JSON.parse(readFileSync(
  new URL('../vectors/source-v6-args-framing.json', import.meta.url), 'utf8'));
const hex = value => Buffer.from(value, 'hex');
const sha256 = value => createHash('sha256').update(value).digest('hex');

test('optional args bstr and support coexist in fixed-order outer framing', () => {
  const expectedTbs = extractSyntheticSignRequestFraming(
    hex(vector.baseRequestMapHex)).toBeSignedBytes();
  assert.equal(sha256(expectedTbs), vector.tbsContentSha256);
  assert.equal(vector.cases.length, 6);
  for (const item of vector.cases) {
    const encoded = hex(item.mapHex);
    assert.equal(encoded.length, item.bytes, item.id);
    assert.equal(sha256(encoded), item.sha256, item.id);
    if (item.framing === 'REJECT') {
      assert.throws(() => extractSyntheticSignRequestFraming(encoded), TypeError,
        item.id);
      continue;
    }
    const framed = extractSyntheticSignRequestFraming(encoded);
    assert.equal(framed.argsPresent, true, item.id);
    assert.deepEqual(framed.toBeSignedBytes(), expectedTbs, item.id);
    assert.equal(framed.argsContentBytes().toString('hex'),
      vector.argsContentHex, item.id);
    assert.equal(framed.encodedArgsFieldBytes().toString('hex'),
      vector.encodedArgsFieldHex, item.id);
    assert.equal(framed.supportRequested,
      item.id === 'args-and-support-outer-bstr', item.id);
    assert.throws(() => decodeSyntheticSignRequest(encoded), TypeError,
      'authenticated signing path still excludes unvalidated args');
  }
});

test('args absence is distinct from present bytes in both existing request controls', () => {
  for (const [mapHex, digest, expectedSupport] of [
    [vector.baseRequestMapHex, vector.baseRequestMapSha256, false],
    [vector.supportOnlyRequestMapHex, vector.supportOnlyRequestMapSha256, true],
  ]) {
    const encoded = hex(mapHex);
    assert.equal(sha256(encoded), digest);
    const framed = extractSyntheticSignRequestFraming(encoded);
    const original = decodeSyntheticSignRequest(encoded);
    assert.equal(framed.argsPresent, false);
    assert.equal(framed.argsContentBytes(), null);
    assert.equal(framed.encodedArgsFieldBytes(), null);
    assert.equal(framed.supportRequested, expectedSupport);
    assert.deepEqual(framed.toBeSignedBytes(), original.toBeSignedBytes());
    assert.deepEqual(framed.encodedTbsFieldBytes(), original.encodedTbsFieldBytes());
  }
});

test('retained args content, encoded bstr and repeated views own separate storage', () => {
  const input = hex(vector.cases[1].mapHex);
  const framed = extractSyntheticSignRequestFraming(input);
  const first = [framed.keyHandleBytes(), framed.toBeSignedBytes(),
    framed.encodedTbsFieldBytes(), framed.argsContentBytes(),
    framed.encodedArgsFieldBytes()];
  const second = [framed.keyHandleBytes(), framed.toBeSignedBytes(),
    framed.encodedTbsFieldBytes(), framed.argsContentBytes(),
    framed.encodedArgsFieldBytes()];
  const returned = [...first, ...second];
  assert.equal(new Set(returned.map(value => value.buffer)).size, returned.length);
  for (const value of returned) {
    assert.notStrictEqual(value.buffer, input.buffer);
    assert.equal(value.buffer.byteLength, value.byteLength);
  }
  input[input.length - 1] ^= 1;
  for (const value of first) value[0] ^= 1;
  assert.equal(framed.argsContentBytes().toString('hex'), vector.argsContentHex);
  assert.equal(framed.encodedArgsFieldBytes().toString('hex'),
    vector.encodedArgsFieldHex);
  assert.equal(sha256(framed.toBeSignedBytes()), vector.tbsContentSha256);
});

test('outer extraction supplies no verdict on nested COSE arguments', () => {
  const base = hex(vector.baseRequestMapHex);
  const malformedNested = Buffer.concat([
    Buffer.from([0xa3]), base.subarray(1), hex('0741ff'),
  ]);
  const framed = extractSyntheticSignRequestFraming(malformedNested);
  assert.equal(framed.argsPresent, true);
  assert.equal(framed.argsContentBytes().toString('hex'), 'ff');
  assert.throws(() => decodeSyntheticSignRequest(malformedNested), TypeError);
});

test('args mutation and byte restoration leave tbs unchanged', () => {
  const original = hex(vector.cases[0].mapHex);
  const changed = Buffer.from(original);
  changed[changed.length - 1] ^= 1;
  assert.notEqual(sha256(changed), vector.cases[0].sha256);
  assert.equal(sha256(extractSyntheticSignRequestFraming(changed).toBeSignedBytes()),
    vector.tbsContentSha256);
  assert.notDeepEqual(extractSyntheticSignRequestFraming(changed).argsContentBytes(),
    hex(vector.argsContentHex));
  changed[changed.length - 1] ^= 1;
  assert.deepEqual(changed, original);
  assert.equal(sha256(changed), vector.cases[0].sha256);
  assert.equal(extractSyntheticSignRequestFraming(changed)
    .argsContentBytes().toString('hex'), vector.argsContentHex);
});

test('native byte subviews retain exact extent and forged byte prototypes fail', () => {
  const original = hex(vector.cases[0].mapHex);
  const backing = new Uint8Array(original.length + 4);
  backing.fill(0xee);
  backing.set(original, 2);
  const subview = backing.subarray(2, original.length + 2);
  const framed = extractSyntheticSignRequestFraming(subview);
  assert.equal(framed.argsContentBytes().toString('hex'), vector.argsContentHex);
  backing.fill(0);
  assert.equal(sha256(framed.toBeSignedBytes()), vector.tbsContentSha256);
  assert.throws(() => extractSyntheticSignRequestFraming(
    Object.create(Uint8Array.prototype)), /native bytes/);
});
