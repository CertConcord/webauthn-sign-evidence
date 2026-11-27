// A pure model of two pinned draft algorithms. This does not parse CBOR or verify WebAuthn.
const algorithms = (value, name) => {
  if (!Array.isArray(value) || value.length === 0 ||
      value.some(item => !Number.isSafeInteger(item)))
    throw new TypeError(`${name} must be a nonempty integer array`);
  return value;
};

export function decodeDraftSupportList(supportList) {
  if (!Array.isArray(supportList) || supportList.length === 0)
    throw new TypeError('supportList must be a nonempty array');
  const parents = algorithms(supportList[0], 'parent algorithms');
  let children = parents;
  let index = 1;
  if (Array.isArray(supportList[index]))
    children = algorithms(supportList[index++], 'child algorithms');

  let supported = false;
  let hasSparseMatrix = false;
  if (typeof supportList[index] === 'boolean') {
    supported = supportList[index++];
    hasSparseMatrix = true;
    if (index === supportList.length)
      throw new TypeError('sparse matrix requires at least one range');
  } else if (index !== supportList.length) {
    throw new TypeError('sparse matrix requires its Boolean');
  }

  const pairs = new Set();
  const key = (parent, child) => `${parent},${child}`;
  if (!hasSparseMatrix || !supported)
    for (const parent of parents)
      for (const child of children) pairs.add(key(parent, child));

  while (index < supportList.length) {
    const parentStart = supportList[index++];
    if (!Number.isSafeInteger(parentStart) || parentStart < 0 || parentStart >= parents.length)
      throw new RangeError('parent matrix index is out of range');
    let parentLength = 1;
    if (Number.isSafeInteger(supportList[index]) && supportList[index] < 0)
      parentLength = 1 - supportList[index++];
    const childStart = supportList[index++];
    if (!Number.isSafeInteger(childStart) || childStart < 0 || childStart >= children.length)
      throw new RangeError('child matrix index is out of range');
    let childLength = 1;
    if (Number.isSafeInteger(supportList[index]) && supportList[index] < 0)
      childLength = 1 - supportList[index++];
    if (parentStart + parentLength > parents.length || childStart + childLength > children.length)
      throw new RangeError('matrix range exceeds algorithm list');
    for (let p = parentStart; p < parentStart + parentLength; p++)
      for (let c = childStart; c < childStart + childLength; c++) {
        const pair = key(parents[p], children[c]);
        if (supported) pairs.add(pair);
        else pairs.delete(pair);
      }
  }

  return {
    parentAlgorithms: [...parents],
    childAlgorithms: [...children],
    pairs: [...pairs].map(pair => pair.split(',').map(Number))
      .sort((a, b) => a[0] - b[0] || a[1] - b[1]),
  };
}

export function chooseDraftSigningAlgorithm(parentAlgorithm, candidates, support) {
  if (!Number.isSafeInteger(parentAlgorithm))
    throw new TypeError('parent algorithm must be an integer');
  algorithms(candidates, 'candidate algorithms');
  let unsupportedCombination = false;
  for (const candidate of candidates) {
    if (support.pairs.some(([parent, child]) =>
      parent === parentAlgorithm && child === candidate))
      return {chosenAlgorithm: candidate};
    if (support.childAlgorithms.includes(candidate)) unsupportedCombination = true;
  }
  return {error: unsupportedCombination ? 3 : 2};
}

// The source's producer choice after an external finding that the preferred
// child attestation would (or would not) be a self attestation. This does not
// determine attestation type, create an attestation object, or verify one.
export function chooseDraftChildAttestationFormat({preferredFormat, wouldSelfAttest}) {
  if (typeof preferredFormat !== 'string' || preferredFormat.length === 0 ||
      typeof wouldSelfAttest !== 'boolean')
    throw new TypeError('Child attestation choice requires format and self-attestation finding');
  return wouldSelfAttest ? 'none' : preferredFormat;
}

// Only the historical PSCP adapter's attestation format gate is represented.
// A true result is not full admission: parent ceremony, chain, policy and possession remain external.
export function historicalPscpChildFormatGate({format, trustedPackedX5c, selfAttested}) {
  return format === 'packed' && trustedPackedX5c === true && selfAttested === false;
}
