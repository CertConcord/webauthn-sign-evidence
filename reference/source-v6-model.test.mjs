import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {chooseDraftChildAttestationFormat, chooseDraftSigningAlgorithm, decodeDraftSupportList,
  historicalPscpChildFormatGate} from './source-v6-model.mjs';

const vector = JSON.parse(readFileSync(new URL('../vectors/source-v6-model.json', import.meta.url)));

test('draft support-list indices yield a sorted parent-by-child matrix', () => {
  for (const item of vector.supportCases)
    assert.deepEqual(decodeDraftSupportList(item.supportList).pairs,
      item.expectedPairs, item.id);
});

test('candidate order distinguishes pair exclusion, later success and unknown algorithm', () => {
  for (const item of vector.selectionCases) {
    const support = decodeDraftSupportList(item.supportList);
    assert.deepEqual(chooseDraftSigningAlgorithm(item.parentAlgorithm,
      item.candidates, support), item.expected, item.id);
  }
  const both = decodeDraftSupportList([[-7], [-9, -300]]);
  assert.deepEqual(chooseDraftSigningAlgorithm(-7, [-9, -300], both),
    {chosenAlgorithm: -9});
  assert.deepEqual(chooseDraftSigningAlgorithm(-7, [-300, -9], both),
    {chosenAlgorithm: -300});
});

test('invalid sparse matrix positions and shapes cannot imply support', () => {
  assert.throws(() => decodeDraftSupportList([[-7], [-9], true, 1, 0]),
    /parent matrix index/);
  assert.throws(() => decodeDraftSupportList([[-7], [-9], true, 0, 1]),
    /child matrix index/);
  assert.throws(() => decodeDraftSupportList([[-7], [-9], true, 0, -1, 0]),
    /matrix range exceeds/);
  assert.throws(() => decodeDraftSupportList([[-7], [-9], 0, 0]),
    /requires its Boolean/);
  assert.throws(() => decodeDraftSupportList([[-7], [-9], true]),
    /requires at least one range/);
});

test('child self attestation fallback and historical PSCP format gate stay distinct', () => {
  for (const item of vector.childAttestationCases) {
    assert.equal(chooseDraftChildAttestationFormat(item.producerInput),
      item.expectedProducerFormat, item.id);
    assert.equal(historicalPscpChildFormatGate(item.presented),
      item.expectedPscpFormatGate, item.id);
  }
  assert.notEqual(vector.childAttestationCases[0].presented.format,
    chooseDraftChildAttestationFormat(vector.childAttestationCases[0].producerInput));
  assert.equal(vector.childAttestationCases[1].presented.format,
    chooseDraftChildAttestationFormat(vector.childAttestationCases[1].producerInput));
  assert.equal(vector.childAttestationCases[2].expectedPscpFormatGate, true);
  assert.throws(() => chooseDraftChildAttestationFormat({preferredFormat: 'packed'}),
    /self-attestation finding/);
});
