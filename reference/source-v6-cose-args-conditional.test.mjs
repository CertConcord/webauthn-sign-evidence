import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {classifyConditionalCoseArgs} from './source-v6-cose-args-conditional.mjs';
import {extractSyntheticSignRequestFraming} from './source-v6-cbor-boundary.mjs';

const vector = JSON.parse(readFileSync(
  new URL('../vectors/source-v6-cose-args-conditional.json', import.meta.url), 'utf8'));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

test('same raw empty args map carries both explicit conditional interpretations', () => {
  const strict = vector.cases.find(item => item.id === 'empty-map-strict-structure-is-five');
  const generic = vector.cases.find(item => item.id === 'empty-map-generic-map-is-six');
  assert.equal(strict.outerHex, generic.outerHex);
  assert.equal(strict.argsContentHex, generic.argsContentHex);
  assert.notEqual(strict.decoderFinding.kind, generic.decoderFinding.kind);
  assert.notEqual(strict.expected, generic.expected);
});

test('frozen outer bytes and supplied findings follow the proposal order conditionally', () => {
  for (const item of vector.cases) {
    const outerBytes = Buffer.from(item.outerHex, 'hex');
    assert.equal(sha256(outerBytes), item.outerSha256, item.id);
    const outer = extractSyntheticSignRequestFraming(outerBytes);
    assert.equal(Buffer.from(outer.toBeSignedBytes()).toString('hex'), '616263');
    assert.equal(outer.argsPresent, item.argsContentHex !== null, item.id);
    assert.equal(outer.argsPresent ?
      Buffer.from(outer.argsContentBytes()).toString('hex') : null,
      item.argsContentHex, item.id);
    assert.equal(outer.argsPresent ? sha256(outer.argsContentBytes()) : null,
      item.argsContentSha256, item.id);
    assert.equal(classifyConditionalCoseArgs({
      keyHandleVerified: true,
      trustedChosenAlg: vector.trustedChosenAlg,
      decoderFinding: item.decoderFinding,
    }), item.expected, item.id);
  }
});

test('no classification is available without a trusted key-handle finding', () => {
  const valid = {kind: 'map', alg: -7};
  assert.throws(() => classifyConditionalCoseArgs({
    keyHandleVerified: false, trustedChosenAlg: -7, decoderFinding: valid,
  }), /verified key handle/);
  assert.throws(() => classifyConditionalCoseArgs({
    keyHandleVerified: true, trustedChosenAlg: -2147483649, decoderFinding: valid,
  }), /trusted chosen algorithm/);
  assert.throws(() => classifyConditionalCoseArgs({
    keyHandleVerified: true, trustedChosenAlg: -7,
    decoderFinding: {kind: 'map', alg: -2147483649},
  }), /decoded integer algorithm/);
});
