import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {restoreSyntheticOuterEvidence} from './outer-evidence.mjs';

const magic = Buffer.from('CCS2', 'ascii');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function ownedBytes(value, name) {
  if (!types.isUint8Array(value))
    throw new TypeError(name + ' must be nonempty native bytes');
  const snapshot = new Uint8Array(value);
  if (snapshot.byteLength === 0)
    throw new TypeError(name + ' must be nonempty native bytes');
  return Buffer.from(snapshot.buffer);
}

function lengthField(bytes) {
  const count = bytes === null ? 0 : bytes.length;
  if (count > 0xffffffff) throw new RangeError('Synthetic field is too long');
  const field = Buffer.alloc(4);
  field.writeUInt32BE(count);
  return field;
}

function record(snapshotBytes, requestBytes = null, responseBytes = null) {
  const snapshot = ownedBytes(snapshotBytes, 'frozen outer snapshot');
  const outer = restoreSyntheticOuterEvidence(snapshot);
  if (outer.timestampResponseDerBytes() === null ||
      outer.unverifiedLogArtifactBytes() === null)
    throw new TypeError('Freeze the first response and log bytes before the later target');
  const request = requestBytes === null ? null :
    ownedBytes(requestBytes, 'later timestamp request');
  const response = responseBytes === null ? null :
    ownedBytes(responseBytes, 'later timestamp response');
  if (response !== null && request === null)
    throw new TypeError('Later response requires a retained request');
  return Object.freeze({
    targetSnapshotBytes: () => ownedBytes(snapshot, 'frozen outer snapshot'),
    targetSha256: () => sha256(snapshot),
    laterRequestDerBytes: () => request === null ? null :
      ownedBytes(request, 'later timestamp request'),
    laterResponseDerBytes: () => response === null ? null :
      ownedBytes(response, 'later timestamp response'),
    fingerprints: () => Object.freeze({
      targetSnapshotSha256: sha256(snapshot),
      laterRequestDerSha256: request === null ? null : sha256(request),
      laterResponseDerSha256: response === null ? null : sha256(response),
    }),
    withLaterRequestDer(bytes) {
      if (request !== null) throw new TypeError('Later request already retained');
      return record(snapshot, ownedBytes(bytes, 'later timestamp request'));
    },
    withLaterResponseDer(bytes) {
      if (request === null) throw new TypeError('Retain later request first');
      if (response !== null) throw new TypeError('Later response already retained');
      return record(snapshot, request, ownedBytes(bytes, 'later timestamp response'));
    },
    serializeBytes() {
      return ownedBytes(Buffer.concat([
        magic, lengthField(snapshot), snapshot,
        lengthField(request), request ?? Buffer.alloc(0),
        lengthField(response), response ?? Buffer.alloc(0),
      ]), 'later outer record');
    },
  });
}

// This selects a synthetic second target; it does not validate a TSA or log proof.
export function freezeSyntheticLaterTimestampTarget(outerSnapshotBytes) {
  return record(outerSnapshotBytes);
}

export function restoreSyntheticLaterTimestampRecord(serializedBytes) {
  const source = ownedBytes(serializedBytes, 'later outer record');
  let offset = 0;
  if (source.length < magic.length || !source.subarray(0, magic.length).equals(magic))
    throw new TypeError('Unexpected later outer record format');
  offset += magic.length;
  const field = () => {
    if (source.length - offset < 4) throw new TypeError('Truncated later outer field length');
    const size = source.readUInt32BE(offset);
    offset += 4;
    if (size > source.length - offset) throw new TypeError('Truncated later outer field');
    const bytes = size === 0 ? null : source.subarray(offset, offset + size);
    offset += size;
    return bytes;
  };
  const snapshot = field();
  const request = field();
  const response = field();
  if (offset !== source.length) throw new TypeError('Trailing later outer record bytes');
  if (snapshot === null) throw new TypeError('Frozen outer snapshot is required');
  return record(snapshot, request, response);
}
