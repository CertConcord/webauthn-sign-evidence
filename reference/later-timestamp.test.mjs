import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {freezeSyntheticOuterEvidence, restoreSyntheticOuterEvidence} from './outer-evidence.mjs';
import {freezeSyntheticLaterTimestampTarget,
  restoreSyntheticLaterTimestampRecord} from './later-timestamp.mjs';

const load = path => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const compact = load('../vectors/optional-jws.json');
const firstResponse = load('../vectors/optional-jws-response.json');
const outerVector = load('../vectors/outer-evidence.json');
const vector = load('../vectors/later-timestamp.json');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const jws = Buffer.from(compact.compactAscii, 'ascii');
const firstRequest = Buffer.from(compact.timestampRequestDerHex, 'hex');
const firstToken = Buffer.from(firstResponse.positiveResponseDerBase64, 'base64');
const log = Buffer.from(outerVector.unverifiedLogArtifactHex, 'hex');
const laterRequest = Buffer.from(vector.laterRequestDerBase64, 'base64');
const laterResponse = Buffer.from(vector.laterResponseDerBase64, 'base64');
const originalOuter = freezeSyntheticOuterEvidence(jws, firstRequest)
  .withTimestampResponse(firstToken).withUnverifiedLogArtifact(log);
const snapshot = originalOuter.serializeBytes();
const target = freezeSyntheticLaterTimestampTarget(snapshot);
const complete = target.withLaterRequestDer(laterRequest)
  .withLaterResponseDer(laterResponse);

function verifyResponse(data, request, response, epoch, mode = 'data') {
  const directory = mkdtempSync(join(tmpdir(), 'webauthn-later-ts-'));
  try {
    const dataPath = join(directory, 'data.bin');
    const requestPath = join(directory, 'request.der');
    const responsePath = join(directory, 'response.der');
    const rootPath = join(directory, 'test-root.pem');
    writeFileSync(dataPath, data);
    writeFileSync(requestPath, request);
    writeFileSync(responsePath, response);
    writeFileSync(rootPath, firstResponse.testRootPem);
    const input = mode === 'query' ? ['-queryfile', requestPath] : ['-data', dataPath];
    const result = spawnSync('openssl', ['ts', '-verify', ...input,
      '-in', responsePath, '-CAfile', rootPath, '-attime', String(epoch)], {
      encoding: 'utf8', timeout: 15_000,
    });
    if (result.error) throw result.error;
    return result;
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
}

const verifyFirst = (record, mode = 'data') => verifyResponse(
  record.compactJwsBytes(), record.timestampRequestDerBytes(),
  record.timestampResponseDerBytes(), outerVector.testVerificationEpochSeconds, mode);
const verifyLater = (record, mode = 'data') => verifyResponse(
  record.targetSnapshotBytes(), record.laterRequestDerBytes(),
  record.laterResponseDerBytes(), vector.testVerificationEpochSeconds, mode);

test('second request targets the exact frozen outer snapshot after response and log', () => {
  assert.deepEqual(snapshot, Buffer.from(vector.frozenOuterSnapshotBase64, 'base64'));
  assert.equal(snapshot.length, vector.frozenOuterSnapshotLength);
  assert.equal(sha256(snapshot), vector.frozenOuterSnapshotSha256);
  assert.equal(sha256(jws), vector.firstCompleteJwsSha256);
  assert.equal(sha256(laterRequest), vector.laterRequestDerSha256);
  assert.equal(sha256(laterResponse), vector.laterResponseDerSha256);
  assert.equal(laterRequest.indexOf(Buffer.from(vector.frozenOuterSnapshotSha256, 'hex')) > 0,
    true);
  assert.equal(verifyFirst(originalOuter).status, 0);
  assert.equal(verifyFirst(originalOuter, 'query').status, 0);
  assert.equal(verifyLater(complete).status, 0);
  assert.equal(verifyLater(complete, 'query').status, 0);
  assert.deepEqual(vector.claims, {
    firstTimestampTrustEstablished: false,
    laterTimestampTrustEstablished: false,
    logProofValidated: false,
    rfc5544OrErsConformant: false,
  });
});

test('second transaction stays outside its target and binary record round trips', () => {
  assert.equal(target.laterRequestDerBytes(), null);
  assert.equal(target.laterResponseDerBytes(), null);
  assert.equal(target.targetSha256(), vector.frozenOuterSnapshotSha256);
  assert.equal(complete.targetSha256(), target.targetSha256());
  assert.deepEqual(complete.targetSnapshotBytes(), snapshot);
  assert.deepEqual(complete.laterRequestDerBytes(), laterRequest);
  assert.deepEqual(complete.laterResponseDerBytes(), laterResponse);
  const encoded = complete.serializeBytes();
  const restored = restoreSyntheticLaterTimestampRecord(encoded);
  assert.deepEqual(restored.targetSnapshotBytes(), snapshot);
  assert.deepEqual(restored.laterRequestDerBytes(), laterRequest);
  assert.deepEqual(restored.laterResponseDerBytes(), laterResponse);
  assert.deepEqual(restored.serializeBytes(), encoded);
  assert.deepEqual(restored.fingerprints(), complete.fingerprints());
  assert.equal(verifyLater(restored).status, 0);
});

test('outer JSON reserialization changes only the second byte target', () => {
  const fields = JSON.parse(snapshot.toString('utf8'));
  const reordered = Buffer.from(JSON.stringify({
    unverifiedLogArtifactBase64: fields.unverifiedLogArtifactBase64,
    timestampResponseDerBase64: fields.timestampResponseDerBase64,
    timestampRequestDerBase64: fields.timestampRequestDerBase64,
    compactJwsBase64: fields.compactJwsBase64,
    format: fields.format,
  }, null, 2), 'utf8');
  assert.equal(sha256(reordered), vector.reorderedSnapshotSha256);
  assert.deepEqual(restoreSyntheticOuterEvidence(reordered).fingerprints(),
    originalOuter.fingerprints());
  const changedTarget = freezeSyntheticLaterTimestampTarget(reordered)
    .withLaterRequestDer(laterRequest).withLaterResponseDer(laterResponse);
  assert.notEqual(changedTarget.targetSha256(), complete.targetSha256());
  assert.equal(verifyFirst(restoreSyntheticOuterEvidence(reordered)).status, 0);
  assert.notEqual(verifyLater(changedTarget).status, 0);
  assert.equal(verifyLater(restoreSyntheticLaterTimestampRecord(
    complete.serializeBytes())).status, 0);
});

test('changed log bytes break the second edge while leaving the first edge intact', () => {
  const changedLog = Buffer.from(log);
  changedLog[0] ^= 1;
  const changedOuter = freezeSyntheticOuterEvidence(jws, firstRequest)
    .withTimestampResponse(firstToken).withUnverifiedLogArtifact(changedLog);
  const changedSnapshot = changedOuter.serializeBytes();
  assert.equal(sha256(changedSnapshot), vector.changedLogSnapshotSha256);
  assert.equal(verifyFirst(changedOuter).status, 0);
  const changedTarget = freezeSyntheticLaterTimestampTarget(changedSnapshot)
    .withLaterRequestDer(laterRequest).withLaterResponseDer(laterResponse);
  assert.notEqual(verifyLater(changedTarget).status, 0);
});

test('changed JWS bytes break both first and second edges', () => {
  const changedJws = Buffer.from(jws);
  changedJws[changedJws.lastIndexOf(0x2e) + 1] ^= 1;
  const changedOuter = freezeSyntheticOuterEvidence(changedJws, firstRequest)
    .withTimestampResponse(firstToken).withUnverifiedLogArtifact(log);
  const changedSnapshot = changedOuter.serializeBytes();
  assert.equal(sha256(changedSnapshot), vector.changedJwsSnapshotSha256);
  assert.notEqual(verifyFirst(changedOuter).status, 0);
  const changedTarget = freezeSyntheticLaterTimestampTarget(changedSnapshot)
    .withLaterRequestDer(laterRequest).withLaterResponseDer(laterResponse);
  assert.notEqual(verifyLater(changedTarget).status, 0);
  assert.equal(verifyFirst(originalOuter).status, 0);
  assert.equal(verifyLater(complete).status, 0);
});

test('changing only the second request or response requires its own validation', () => {
  const changedRequest = Buffer.from(laterRequest);
  const digest = Buffer.from(vector.frozenOuterSnapshotSha256, 'hex');
  assert.equal(changedRequest.lastIndexOf(digest), changedRequest.indexOf(digest));
  changedRequest[changedRequest.indexOf(digest)] ^= 1;
  const withChangedRequest = target.withLaterRequestDer(changedRequest)
    .withLaterResponseDer(laterResponse);
  assert.equal(withChangedRequest.targetSha256(), target.targetSha256());
  assert.equal(verifyLater(withChangedRequest).status, 0);
  assert.notEqual(verifyLater(withChangedRequest, 'query').status, 0);
  const changedResponse = Buffer.from(laterResponse);
  assert.equal(changedResponse.lastIndexOf(digest), changedResponse.indexOf(digest));
  changedResponse[changedResponse.indexOf(digest)] ^= 1;
  const withChangedResponse = target.withLaterRequestDer(laterRequest)
    .withLaterResponseDer(changedResponse);
  assert.equal(withChangedResponse.targetSha256(), target.targetSha256());
  assert.notEqual(verifyLater(withChangedResponse).status, 0);
  assert.equal(verifyFirst(originalOuter).status, 0);
});

test('later record enforces order, exact lengths and native owned byte copies', () => {
  assert.throws(() => target.withLaterResponseDer(laterResponse), /request first/);
  assert.throws(() => complete.withLaterRequestDer(laterRequest), /already retained/);
  assert.throws(() => complete.withLaterResponseDer(laterResponse), /already retained/);
  const incomplete = freezeSyntheticOuterEvidence(jws, firstRequest)
    .withTimestampResponse(firstToken);
  assert.throws(() => freezeSyntheticLaterTimestampTarget(incomplete.serializeBytes()),
    /response and log/);
  const forged = Object.create(Uint8Array.prototype);
  forged[Symbol.iterator] = function* () { yield 1; };
  assert.throws(() => freezeSyntheticLaterTimestampTarget(forged), /native bytes/);
  const encoded = complete.serializeBytes();
  for (const malformed of [
    Buffer.concat([encoded, Buffer.from([0])]),
    encoded.subarray(0, encoded.length - 1),
    Buffer.from([0, ...encoded.subarray(1)]),
  ]) {
    assert.throws(() => restoreSyntheticLaterTimestampRecord(malformed));
  }
  const firstCopy = complete.targetSnapshotBytes();
  const secondCopy = complete.targetSnapshotBytes();
  assert.notStrictEqual(firstCopy.buffer, secondCopy.buffer);
  firstCopy[0] ^= 1;
  assert.deepEqual(complete.targetSnapshotBytes(), snapshot);
});
