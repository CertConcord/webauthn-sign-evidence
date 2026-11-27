// A pure ordering model for two unresolved proposal checks, after a separately
// verified key handle supplies chosenAlg. It does not decode CBOR or sign data.
const isSignedLong = value => Number.isInteger(value) &&
  value >= -2147483648 && value <= 2147483647;

export function classifyConditionalCoseArgs({
  keyHandleVerified, trustedChosenAlg, decoderFinding,
}) {
  if (keyHandleVerified !== true)
    throw new TypeError('A verified key handle is required before args checks');
  if (!isSignedLong(trustedChosenAlg))
    throw new TypeError('A signed 32-bit trusted chosen algorithm is required');
  if (decoderFinding === null || typeof decoderFinding !== 'object' ||
      Array.isArray(decoderFinding))
    throw new TypeError('A supplied decoder finding is required');
  const kind = decoderFinding.kind;
  const hasAlg = Object.hasOwn(decoderFinding, 'alg');
  if (kind === 'omitted' || kind === 'invalid') {
    if (hasAlg) throw new TypeError('Non-map finding cannot carry alg');
    return kind === 'omitted' ? 'ARGS_STAGE_SKIPPED' : 'CONDITIONAL_ERROR_5';
  }
  if (kind !== 'map') throw new TypeError('Unknown supplied decoder finding');
  if (!hasAlg) return 'CONDITIONAL_ERROR_6';
  const alg = decoderFinding.alg;
  if (!isSignedLong(alg))
    throw new TypeError('A decoded integer algorithm is required in this model');
  return alg === trustedChosenAlg ? 'ARGS_ALG_STAGE_PASSED' :
    'CONDITIONAL_ERROR_6';
}

// Comparison-only continuation after the existing conditional 5/6 checks.
// A separate decoder supplies integer additional-parameter labels, while a
// separately selected algorithm policy identifies required and applicable
// labels. The pinned WebAuthn proposals do not select these member rules.
function labels(value, name) {
  if (!Array.isArray(value))
    throw new TypeError(`${name} must be distinct integer additional labels`);
  const length = value.length;
  if (!Number.isSafeInteger(length) || length < 0 || length > 64)
    throw new TypeError(`${name} must be distinct integer additional labels`);
  const snapshot = [];
  for (let index = 0; index < length; index += 1) {
    const item = value[index];
    if (!Number.isSafeInteger(item) || Object.is(item, -0) || item === 3)
      throw new TypeError(`${name} must be distinct integer additional labels`);
    snapshot.push(item);
  }
  if (new Set(snapshot).size !== snapshot.length)
    throw new TypeError(`${name} must be distinct integer additional labels`);
  return snapshot;
}

export function classifyConditionalCoseArgsParameters(input) {
  const chosenAlg = input.trustedChosenAlg;
  const decoderFinding = input.decoderFinding;
  const prior = classifyConditionalCoseArgs({
    keyHandleVerified: input.keyHandleVerified,
    trustedChosenAlg: chosenAlg,
    decoderFinding,
  });
  if (prior === 'CONDITIONAL_ERROR_5' || prior === 'CONDITIONAL_ERROR_6')
    return prior;
  const policy = input.parameterPolicy;
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy) ||
      policy.algorithm !== chosenAlg)
    throw new TypeError('An algorithm-matched parameter policy is required');
  const required = labels(policy.requiredAdditionalLabels, 'required labels');
  const applicable = labels(policy.applicableAdditionalLabels, 'applicable labels');
  if (required.some(label => !applicable.includes(label)))
    throw new TypeError('Required labels must be applicable');
  // Under the selected strict member policy, absent args lacks required
  // labels. A policy applying the signing primitive's empty-context default
  // can instead select no required additional labels. Neither is universal.
  if (prior === 'ARGS_STAGE_SKIPPED')
    return required.length > 0 ? 'CONDITIONAL_ERROR_7' :
      'ARGS_PARAMETER_STAGE_PASSED';
  const supplied = labels(decoderFinding.additionalParameterLabels,
    'decoded labels');
  if (required.some(label => !supplied.includes(label)))
    return 'CONDITIONAL_ERROR_7';
  if (supplied.some(label => !applicable.includes(label)))
    return 'CONDITIONAL_ERROR_8';
  return 'ARGS_PARAMETER_STAGE_PASSED';
}
