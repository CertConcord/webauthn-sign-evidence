import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {extractSyntheticSignRequestFraming} from './source-v6-cbor-boundary.mjs';
import {classifyConditionalCoseArgsParameters} from
  './source-v6-cose-args-conditional.mjs';

const vector = JSON.parse(readFileSync(new URL(
  '../vectors/source-v6-cose-args-parameter-conditional.json', import.meta.url),
'utf8'));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// Independent reader for only the seven frozen nested examples. Production
// code still receives a decoder finding rather than parsing COSE_Sign_Args.
function inspectFrozenNestedArgs(bytes) {
  if (bytes === null) return {kind: 'omitted'};
  const integer = offset => {
    if (offset >= bytes.length) throw new TypeError('truncated integer');
    const lead = bytes[offset];
    const major = lead >> 5;
    const additional = lead & 31;
    if (major !== 0 && major !== 1) throw new TypeError('expected integer');
    let magnitude;
    let next = offset + 1;
    if (additional < 24) magnitude = additional;
    else if (additional === 24 && next < bytes.length)
      magnitude = bytes[next++];
    else if (additional === 25 && bytes.length - next >= 2) {
      magnitude = bytes.readUInt16BE(next);
      next += 2;
    } else throw new TypeError('unsupported integer');
    return {value: major === 0 ? magnitude : -1 - magnitude, next};
  };
  try {
    const members = bytes[0] - 0xa0;
    if (members < 1 || members > 3) throw new TypeError('expected small map');
    let offset = 1;
    let alg;
    const additionalParameterLabels = [];
    const seen = new Set();
    for (let index = 0; index < members; index += 1) {
      const key = integer(offset);
      offset = key.next;
      if (seen.has(key.value)) throw new TypeError('duplicate key');
      seen.add(key.value);
      if (key.value === 3) {
        const value = integer(offset);
        alg = value.value;
        offset = value.next;
      } else if (key.value === -1) {
        if (bytes[offset++] !== 0x40) throw new TypeError('expected empty context bstr');
        additionalParameterLabels.push(-1);
      } else if (key.value === 4) {
        offset = integer(offset).next;
        additionalParameterLabels.push(4);
      } else throw new TypeError('unexpected example label');
    }
    if (offset !== bytes.length || alg === undefined)
      throw new TypeError('trailing or absent alg');
    return {kind: 'map', alg, additionalParameterLabels};
  } catch {
    return {kind: 'invalid'};
  }
}

test('original outer bytes and supplied findings keep the conditional error order', () => {
  assert.equal(vector.cases.length, 10);
  for (const item of vector.cases) {
    const source = Buffer.from(item.outerHex, 'hex');
    assert.equal(source.toString('hex'), item.outerHex, item.id);
    assert.equal(sha256(source), item.outerSha256, item.id);
    const outer = extractSyntheticSignRequestFraming(source);
    assert.equal(outer.toBeSignedBytes().toString('hex'), '616263', item.id);
    const args = outer.argsContentBytes();
    assert.equal(args === null ? null : args.toString('hex'),
      item.argsContentHex, item.id);
    assert.equal(args === null ? null : sha256(args),
      item.argsContentSha256, item.id);
    assert.deepEqual(inspectFrozenNestedArgs(args), item.decoderFinding, item.id);
    assert.equal(classifyConditionalCoseArgsParameters({
      keyHandleVerified: true,
      trustedChosenAlg: vector.trustedChosenAlg,
      decoderFinding: item.decoderFinding,
      parameterPolicy: item.parameterPolicy,
    }), item.expected, item.id);
  }
});

test('the same omitted or context-free bytes follow the selected policy', () => {
  const find = id => vector.cases.find(item => item.id === id);
  const omitted = find('omitted-args-competing-interpretations');
  const omittedDefaulted = find(
    'omitted-args-competing-interpretations-empty-default-interpretation');
  const missing = find('missing-context');
  const defaulted = find('missing-context-empty-default-interpretation');
  const overlap = find('missing-context-precedes-unknown');
  const overlapDefaulted = find(
    'missing-context-precedes-unknown-empty-default-interpretation');
  assert.equal(omitted.outerHex, omittedDefaulted.outerHex);
  assert.equal(omitted.expected, 'CONDITIONAL_ERROR_7');
  assert.equal(omittedDefaulted.expected, 'ARGS_PARAMETER_STAGE_PASSED');
  assert.equal(missing.outerHex, defaulted.outerHex);
  assert.equal(missing.argsContentSha256, defaulted.argsContentSha256);
  assert.equal(missing.expected, 'CONDITIONAL_ERROR_7');
  assert.equal(defaulted.expected, 'ARGS_PARAMETER_STAGE_PASSED');
  assert.equal(overlap.outerHex, overlapDefaulted.outerHex);
  assert.equal(overlap.expected, 'CONDITIONAL_ERROR_7');
  assert.equal(overlapDefaulted.expected, 'CONDITIONAL_ERROR_8');
});

test('invalid supplied policy and decoder labels cannot create a capability result', () => {
  const input = {
    keyHandleVerified: true, trustedChosenAlg: -303,
    decoderFinding: {kind: 'map', alg: -303,
      additionalParameterLabels: [-1]},
    parameterPolicy: {algorithm: -303, requiredAdditionalLabels: [-1],
      applicableAdditionalLabels: [-1]},
  };
  assert.throws(() => classifyConditionalCoseArgsParameters({
    ...input, keyHandleVerified: false,
  }), /verified key handle/);
  assert.throws(() => classifyConditionalCoseArgsParameters({
    ...input, parameterPolicy: {...input.parameterPolicy, algorithm: -7},
  }), /algorithm-matched parameter policy/);
  assert.throws(() => classifyConditionalCoseArgsParameters({
    ...input, parameterPolicy: {...input.parameterPolicy,
      applicableAdditionalLabels: []},
  }), /Required labels must be applicable/);
  assert.throws(() => classifyConditionalCoseArgsParameters({
    ...input, decoderFinding: {...input.decoderFinding,
      additionalParameterLabels: [-1, -1]},
  }), /distinct integer additional labels/);
});

test('a supplied parameter label and chosen algorithm are each fixed by one read', () => {
  let algorithmReads = 0;
  let labelReads = 0;
  const supplied = [-1];
  Object.defineProperty(supplied, 0, {get() {
    labelReads += 1;
    return labelReads === 1 ? -1 : 4;
  }});
  const input = {
    keyHandleVerified: true,
    get trustedChosenAlg() {
      algorithmReads += 1;
      return algorithmReads === 1 ? -303 : -7;
    },
    decoderFinding: {kind: 'map', alg: -303,
      additionalParameterLabels: supplied},
    parameterPolicy: {algorithm: -303, requiredAdditionalLabels: [-1],
      applicableAdditionalLabels: [-1]},
  };
  assert.equal(classifyConditionalCoseArgsParameters(input),
    'ARGS_PARAMETER_STAGE_PASSED');
  assert.equal(algorithmReads, 1);
  assert.equal(labelReads, 1);
});
