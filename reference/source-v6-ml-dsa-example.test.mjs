import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {chooseDraftSigningAlgorithm, decodeDraftSupportList} from './source-v6-model.mjs';

const example = JSON.parse(readFileSync(
  new URL('../vectors/source-v6-ml-dsa-example.json', import.meta.url)));
const support = decodeDraftSupportList(example.supportList);
const contains = ([parent, child]) => support.pairs.some(([p, c]) =>
  p === parent && c === child);

test('published v6 ML-DSA example excludes exactly its eight indexed pairs', () => {
  assert.equal(support.parentAlgorithms.length * support.childAlgorithms.length,
    example.possiblePairs);
  assert.equal(support.pairs.length, example.expectedSupportedPairs);
  assert.equal(example.excludedPairs.length,
    example.possiblePairs - example.expectedSupportedPairs);
  for (const pair of example.excludedPairs)
    assert.equal(contains(pair), false, `excluded ${pair}`);
  for (const pair of example.retainedPairs)
    assert.equal(contains(pair), true, `retained ${pair}`);
});

test('same published matrix distinguishes pair failure and later compatible child', () => {
  for (const item of example.selectionCases)
    assert.deepEqual(chooseDraftSigningAlgorithm(item.parentAlgorithm,
      item.candidates, support), item.expected, item.id);
});
