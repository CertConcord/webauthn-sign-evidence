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
