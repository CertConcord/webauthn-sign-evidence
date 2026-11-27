import {types} from 'node:util';
import {decodeDraftSupportList} from './source-v6-model.mjs';

// This local fixed-order subset admits at most three 65,535-byte bstr fields,
// their three-byte headers and one-byte keys, the map header and support:true.
// It is a parser bound, not a WebAuthn or CTAP message-size requirement.
const MAX_SYNTHETIC_MAP_BYTES = 1 + 3 * (1 + 3 + 65535) + 2;
const nativeByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;

function ownedBytes(value, name) {
  if (!types.isUint8Array(value))
    throw new TypeError(`${name} must be native bytes`);
  return Buffer.from(new Uint8Array(value).buffer);
}

function snapshotSyntheticMap(value) {
  if (!types.isUint8Array(value))
    throw new TypeError('synthetic extension map must be native bytes');
  const length = nativeByteLength.call(value);
  if (length > MAX_SYNTHETIC_MAP_BYTES)
    throw new TypeError('synthetic CBOR map exceeds local limit');
  const snapshot = Buffer.alloc(length);
  try {
    Uint8Array.prototype.set.call(snapshot, value);
  } catch (cause) {
    throw new TypeError('synthetic extension map changed during snapshot', {cause});
  }
  return snapshot;
}

// A deliberately narrow view of the draft's inner authenticator extension map.
// It accepts the fixed sign member order, with optional support as the last
// member. It does not parse a WebAuthn response or authenticate a key.
function readByteString(source, start) {
  let offset = start;
  const initial = source[offset++];
  let length;
  if (initial >= 0x40 && initial <= 0x57) {
    length = initial - 0x40;
  } else if (initial === 0x58) {
    if (offset >= source.length) throw new TypeError('Truncated CBOR byte-string length');
    length = source[offset++];
    if (length < 24) throw new TypeError('Noncanonical CBOR byte-string length');
  } else if (initial === 0x59) {
    if (source.length - offset < 2)
      throw new TypeError('Truncated CBOR byte-string length');
    length = source.readUInt16BE(offset);
    offset += 2;
    if (length <= 255) throw new TypeError('Noncanonical CBOR byte-string length');
  } else {
    throw new TypeError('Expected a definite CBOR byte string');
  }
  if (length > source.length - offset)
    throw new TypeError('Truncated CBOR byte-string content');
  return {
    content: ownedBytes(source.subarray(offset, offset + length), 'CBOR content'),
    encoded: ownedBytes(source.subarray(start, offset + length), 'CBOR field'),
    next: offset + length,
  };
}

function decodeMap(sourceBytes, members) {
  const source = snapshotSyntheticMap(sourceBytes);
  const hasSupport = source[0] === 0xa0 + members.length + 1;
  if (source[0] !== 0xa0 + members.length && !hasSupport)
    throw new TypeError('Unexpected synthetic extension map size');
  let offset = 1;
  const fields = [];
  for (const expectedKey of members) {
    if (source[offset++] !== expectedKey)
      throw new TypeError('Unexpected synthetic extension map key');
    const field = readByteString(source, offset);
    fields.push(field);
    offset = field.next;
  }
  if (!hasSupport && offset !== source.length)
    throw new TypeError('Trailing synthetic extension map bytes');
  return {
    fields,
    supportField: hasSupport ? ownedBytes(source.subarray(offset), 'support field') : null,
  };
}

function readArgument(source, offset) {
  if (offset >= source.length) throw new TypeError('Truncated CBOR value');
  const initial = source[offset];
  const additional = initial & 0x1f;
  if (additional < 24) return {value: additional, next: offset + 1};
  const widths = {24: 1, 25: 2, 26: 4, 27: 8};
  const width = widths[additional];
  if (!width || source.length - offset - 1 < width)
    throw new TypeError('Unsupported or truncated CBOR argument');
  let value = 0n;
  for (let index = 0; index < width; index += 1)
    value = (value << 8n) + BigInt(source[offset + 1 + index]);
  const minimum = {1: 24n, 2: 256n, 4: 65536n, 8: 4294967296n}[width];
  if (value < minimum || value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new TypeError('Noncanonical or unsafe CBOR argument');
  return {value: Number(value), next: offset + width + 1};
}

function decodeSupportValue(source, offset, depth) {
  if (offset >= source.length) throw new TypeError('Truncated support value');
  const initial = source[offset];
  if (initial === 0xf4 || initial === 0xf5)
    return {value: initial === 0xf5, next: offset + 1};
  const major = initial >> 5;
  if (major !== 0 && major !== 1 && major !== 4)
    throw new TypeError('Unsupported support CBOR type');
  const argument = readArgument(source, offset);
  if (major !== 4) {
    if (major === 1 && argument.value >= Number.MAX_SAFE_INTEGER)
      throw new TypeError('Unsafe negative CBOR integer');
    return {value: major === 0 ? argument.value : -1 - argument.value,
            next: argument.next};
  }
  if (depth >= 2 || argument.value > 64)
    throw new TypeError('Unsupported support array depth or length');
  const values = [];
  let next = argument.next;
  for (let index = 0; index < argument.value; index += 1) {
    const item = decodeSupportValue(source, next, depth + 1);
    values.push(item.value);
    next = item.next;
  }
  return {value: values, next};
}

function decodeSupportField(field) {
  if (field[0] !== 8)
    throw new TypeError('Expected support map key');
  const parsed = decodeSupportValue(field, 1, 0);
  if (parsed.next !== field.length || !Array.isArray(parsed.value))
    throw new TypeError('Expected one complete support array');
  decodeDraftSupportList(parsed.value);
  return parsed.value;
}

// Yubico v6 and W3C PR #2078 label kh=2 and tbs=6. The signature covers only
// the content of tbs; its CBOR byte-string header is not part of the input.
export function decodeSyntheticSignRequest(sourceBytes) {
  const {fields: [keyHandle, tbs], supportField} = decodeMap(sourceBytes, [2, 6]);
  if (supportField !== null &&
      (supportField.length !== 2 || supportField[0] !== 8 || supportField[1] !== 0xf5))
    throw new TypeError('Sign support request must be true');
  return Object.freeze({
    keyHandleBytes: () => ownedBytes(keyHandle.content, 'key handle'),
    toBeSignedBytes: () => ownedBytes(tbs.content, 'to-be-signed content'),
    encodedTbsFieldBytes: () => ownedBytes(tbs.encoded, 'encoded tbs field'),
    supportRequested: supportField !== null,
  });
}

// Outer byte framing for the optional args=7 field. The two pinned proposals
// cite a COSE draft version that does not define COSE_Sign_Args, so these bytes
// are deliberately opaque. This extractor does not accept a signing operation
// or classify its COSE parameters, key handle, attestation or CTAP errors.
export function extractSyntheticSignRequestFraming(sourceBytes) {
  const source = snapshotSyntheticMap(sourceBytes);
  const members = source[0] - 0xa0;
  if (members < 2 || members > 4)
    throw new TypeError('Unexpected synthetic extension map size');
  let offset = 1;
  const readField = key => {
    if (source[offset++] !== key)
      throw new TypeError('Unexpected synthetic extension map key');
    const field = readByteString(source, offset);
    offset = field.next;
    return field;
  };
  const keyHandle = readField(2);
  const tbs = readField(6);
  let remaining = members - 2;
  let args = null;
  if (remaining > 0 && source[offset] === 7) {
    args = readField(7);
    remaining -= 1;
  }
  let supportRequested = false;
  if (remaining > 0) {
    if (source[offset++] !== 8 || source[offset++] !== 0xf5)
      throw new TypeError('Sign support request must be true');
    supportRequested = true;
    remaining -= 1;
  }
  if (remaining !== 0 || offset !== source.length)
    throw new TypeError('Trailing or duplicate synthetic extension map fields');
  return Object.freeze({
    keyHandleBytes: () => ownedBytes(keyHandle.content, 'key handle'),
    toBeSignedBytes: () => ownedBytes(tbs.content, 'to-be-signed content'),
    encodedTbsFieldBytes: () => ownedBytes(tbs.encoded, 'encoded tbs field'),
    argsPresent: args !== null,
    argsContentBytes: () => args === null ? null :
      ownedBytes(args.content, 'opaque args content'),
    encodedArgsFieldBytes: () => args === null ? null :
      ownedBytes(args.encoded, 'encoded args field'),
    supportRequested,
  });
}

// The same draft aliases sig=6 in the inner output map. This sample has no
// attestation object or surrounding authData. Omitted support remains unknown.
export function decodeSyntheticSignResponse(sourceBytes) {
  const {fields: [signature], supportField} = decodeMap(sourceBytes, [6]);
  const support = supportField === null ? null : decodeSupportField(supportField);
  return Object.freeze({
    signatureBytes: () => ownedBytes(signature.content, 'signature content'),
    supportList: () => support === null ? null :
      support.map(item => Array.isArray(item) ? [...item] : item),
  });
}
