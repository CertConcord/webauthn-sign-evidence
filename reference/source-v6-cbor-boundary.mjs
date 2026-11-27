import {types} from 'node:util';

function ownedBytes(value, name) {
  if (!types.isUint8Array(value))
    throw new TypeError(`${name} must be native bytes`);
  return Buffer.from(new Uint8Array(value).buffer);
}

// A deliberately narrow view of the draft's inner authenticator extension map.
// It accepts only {kh: bstr, tbs: bstr} or {sig: bstr}, with canonical small
// CBOR lengths. It does not parse a WebAuthn response or authenticate a key.
function decodeMap(sourceBytes, members) {
  const source = ownedBytes(sourceBytes, 'synthetic extension map');
  if (source[0] !== 0xa0 + members.length)
    throw new TypeError('Unexpected synthetic extension map size');
  let offset = 1;
  const fields = [];
  for (const expectedKey of members) {
    if (source[offset++] !== expectedKey)
      throw new TypeError('Unexpected synthetic extension map key');
    const start = offset;
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
    fields.push({
      content: Buffer.from(source.subarray(offset, offset + length)),
      encoded: Buffer.from(source.subarray(start, offset + length)),
    });
    offset += length;
  }
  if (offset !== source.length)
    throw new TypeError('Trailing synthetic extension map bytes');
  return fields;
}

// Yubico v6 and W3C PR #2078 label kh=2 and tbs=6. The signature covers only
// the content of tbs; its CBOR byte-string header is not part of the input.
export function decodeSyntheticSignRequest(sourceBytes) {
  const [keyHandle, tbs] = decodeMap(sourceBytes, [2, 6]);
  return Object.freeze({
    keyHandleBytes: () => Buffer.from(keyHandle.content),
    toBeSignedBytes: () => Buffer.from(tbs.content),
    encodedTbsFieldBytes: () => Buffer.from(tbs.encoded),
  });
}

// The same draft aliases sig=6 in the inner output map. This sample has no
// optional support member, attestation object, or surrounding authData.
export function decodeSyntheticSignResponse(sourceBytes) {
  const [signature] = decodeMap(sourceBytes, [6]);
  return Object.freeze({signatureBytes: () => Buffer.from(signature.content)});
}
