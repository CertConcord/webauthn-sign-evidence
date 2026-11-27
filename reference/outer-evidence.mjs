import {createHash} from 'node:crypto';

const format = 'synthetic-outer-evidence-byte-record-v1';
const keys = ['format', 'compactJwsBase64', 'timestampRequestDerBase64',
  'timestampResponseDerBase64', 'unverifiedLogArtifactBase64'];
const strictUtf8 = new TextDecoder('utf-8', {fatal: true});
const sha256 = value => createHash('sha256').update(value).digest('hex');
const jsonString = /"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;

function copyBytes(value, name) {
  if (!(value instanceof Uint8Array) || value.length === 0)
    throw new TypeError(`${name} must be nonempty bytes`);
  const isolated = Buffer.allocUnsafeSlow(value.length);
  isolated.set(value);
  return isolated;
}

function decodeBase64(value, name, optional = false) {
  if (optional && value === null) return null;
  if (typeof value !== 'string' || value.length === 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    throw new TypeError(`${name} requires canonical base64 bytes`);
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.toString('base64') !== value)
    throw new TypeError(`${name} requires canonical base64 bytes`);
  return decoded;
}

// Parse the restricted outer shape before JSON.parse can discard duplicate names.
function assertUniqueOuterFields(raw) {
  let index = 0;
  const seen = new Set();
  const skipWhitespace = () => {
    while (raw[index] === ' ' || raw[index] === '\t' ||
           raw[index] === '\n' || raw[index] === '\r') index++;
  };
  const readString = () => {
    jsonString.lastIndex = index;
    const match = jsonString.exec(raw);
    if (match === null) throw new TypeError('Expected JSON string');
    index = jsonString.lastIndex;
    return JSON.parse(match[0]);
  };
  const expect = character => {
    if (raw[index] !== character) throw new TypeError('Unexpected outer record syntax');
    index++;
  };
  skipWhitespace();
  expect('{');
  skipWhitespace();
  if (raw[index] !== '}') {
    while (true) {
      const name = readString();
      if (seen.has(name)) throw new TypeError('Duplicate outer record field');
      seen.add(name);
      skipWhitespace();
      expect(':');
      skipWhitespace();
      if (raw[index] === '"') readString();
      else if (raw.startsWith('null', index)) index += 4;
      else throw new TypeError('Unexpected outer record value');
      skipWhitespace();
      if (raw[index] !== ',') break;
      index++;
      skipWhitespace();
    }
  }
  expect('}');
  skipWhitespace();
  if (index !== raw.length) throw new TypeError('Trailing outer record content');
}

function record(compactJws, request, response = null, logArtifact = null) {
  const frozen = copyBytes(compactJws, 'compact JWS');
  const req = copyBytes(request, 'timestamp request');
  const res = response === null ? null : copyBytes(response, 'timestamp response');
  const log = logArtifact === null ? null : copyBytes(logArtifact, 'log artifact');
  return Object.freeze({
    compactJwsBytes: () => copyBytes(frozen, 'compact JWS'),
    timestampRequestDerBytes: () => copyBytes(req, 'timestamp request'),
    timestampResponseDerBytes: () => res === null ? null : copyBytes(res, 'timestamp response'),
    unverifiedLogArtifactBytes: () => log === null ? null : copyBytes(log, 'log artifact'),
    fingerprints: () => Object.freeze({
      compactJwsSha256: sha256(frozen),
      timestampRequestDerSha256: sha256(req),
      timestampResponseDerSha256: res === null ? null : sha256(res),
      unverifiedLogArtifactSha256: log === null ? null : sha256(log),
    }),
    withTimestampResponse(responseBytes) {
      if (res !== null) throw new TypeError('Timestamp response already retained');
      return record(frozen, req, copyBytes(responseBytes, 'timestamp response'));
    },
    withUnverifiedLogArtifact(logBytes) {
      if (res === null) throw new TypeError('Retain timestamp response first');
      if (log !== null) throw new TypeError('Log artifact already retained');
      return record(frozen, req, res, copyBytes(logBytes, 'log artifact'));
    },
    serializeBytes() {
      return copyBytes(Buffer.from(JSON.stringify({
        format,
        compactJwsBase64: frozen.toString('base64'),
        timestampRequestDerBase64: req.toString('base64'),
        timestampResponseDerBase64: res === null ? null : res.toString('base64'),
        unverifiedLogArtifactBase64: log === null ? null : log.toString('base64'),
      }), 'utf8'), 'outer record');
    },
  });
}

// This preserves opaque bytes; it does not validate JWS, TSA or log evidence.
export function freezeSyntheticOuterEvidence(compactJwsBytes, timestampRequestDerBytes) {
  return record(copyBytes(compactJwsBytes, 'compact JWS'),
    copyBytes(timestampRequestDerBytes, 'timestamp request'));
}

export function restoreSyntheticOuterEvidence(serializedBytes) {
  const source = copyBytes(serializedBytes, 'outer record');
  if (source.subarray(0, 3).equals(Buffer.from('efbbbf', 'hex')))
    throw new TypeError('Outer record UTF-8 BOM is not accepted');
  const raw = strictUtf8.decode(source);
  assertUniqueOuterFields(raw);
  const value = JSON.parse(raw);
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort()) ||
      value.format !== format)
    throw new TypeError('Unexpected synthetic outer record shape');
  const frozen = decodeBase64(value.compactJwsBase64, 'compact JWS');
  const request = decodeBase64(value.timestampRequestDerBase64, 'timestamp request');
  const response = decodeBase64(value.timestampResponseDerBase64,
    'timestamp response', true);
  const log = decodeBase64(value.unverifiedLogArtifactBase64,
    'log artifact', true);
  if (log !== null && response === null)
    throw new TypeError('Log artifact requires retained timestamp response');
  return record(frozen, request, response, log);
}
