import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {freezeSyntheticOuterEvidence, restoreSyntheticOuterEvidence} from './outer-evidence.mjs';

const load = path => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const compact = load('../vectors/optional-jws.json');
const timestamp = load('../vectors/optional-jws-response.json');
const vector = load('../vectors/outer-evidence.json');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const artifact = Buffer.from(compact.compactAscii, 'ascii');
const request = Buffer.from(compact.timestampRequestDerHex, 'hex');
const response = Buffer.from(timestamp.positiveResponseDerBase64, 'base64');
const logArtifact = Buffer.from(vector.unverifiedLogArtifactHex, 'hex');
const base = freezeSyntheticOuterEvidence(artifact, request);
const withResponse = base.withTimestampResponse(response);
const withLog = withResponse.withUnverifiedLogArtifact(logArtifact);

function verifyTestResponse(record, mode = 'data') {
  const directory = mkdtempSync(join(tmpdir(), 'webauthn-outer-'));
  try {
    const artifactPath = join(directory, 'artifact.jws');
    const requestPath = join(directory, 'request.der');
    const responsePath = join(directory, 'response.der');
    const rootPath = join(directory, 'test-root.pem');
    writeFileSync(artifactPath, record.compactJwsBytes());
    writeFileSync(requestPath, record.timestampRequestDerBytes());
    writeFileSync(responsePath, record.timestampResponseDerBytes());
    writeFileSync(rootPath, timestamp.testRootPem);
    const target = mode === 'query' ? ['-queryfile', requestPath] : ['-data', artifactPath];
    const result = spawnSync('openssl', ['ts', '-verify', ...target,
      '-in', responsePath, '-CAfile', rootPath, '-attime',
      String(vector.testVerificationEpochSeconds)], {
      encoding: 'utf8', timeout: 15_000,
    });
    if (result.error) throw result.error;
    return result;
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
}

test('outer stages retain raw JWS, request, response and separate opaque log bytes', () => {
  assert.equal(artifact.length, 136);
  assert.equal(vector.compactJwsSha256, compact.compactSha256);
  assert.equal(vector.timestampResponseDerSha256,
    timestamp.fixtureSha256['tsa-test-positive.tsr']);
  assert.equal(base.timestampResponseDerBytes(), null);
  assert.equal(base.unverifiedLogArtifactBytes(), null);
  assert.equal(withResponse.unverifiedLogArtifactBytes(), null);
  assert.deepEqual(withLog.compactJwsBytes(), artifact);
  assert.deepEqual(withLog.timestampRequestDerBytes(), request);
  assert.deepEqual(withLog.timestampResponseDerBytes(), response);
  assert.deepEqual(withLog.unverifiedLogArtifactBytes(), logArtifact);
  assert.deepEqual(withLog.fingerprints(), {
    compactJwsSha256: vector.compactJwsSha256,
    timestampRequestDerSha256: vector.timestampRequestDerSha256,
    timestampResponseDerSha256: vector.timestampResponseDerSha256,
    unverifiedLogArtifactSha256: vector.unverifiedLogArtifactSha256,
  });
  assert.equal(vector.claims.timestampTrustEstablished, false);
  assert.equal(vector.claims.logProofValidated, false);
  assert.equal(vector.claims.laterTimestampTargetSelected, false);
  assert.equal(verifyTestResponse(withLog).status, 0);
  assert.equal(verifyTestResponse(withLog, 'query').status, 0);
});

test('outer serialization and noncanonical JSON rendering preserve every inner octet', () => {
  const serialized = withLog.serializeBytes();
  const parsed = JSON.parse(serialized.toString('utf8'));
  assert.equal(parsed.format, vector.format);
  const rendered = Buffer.from(JSON.stringify({
    unverifiedLogArtifactBase64: parsed.unverifiedLogArtifactBase64,
    timestampResponseDerBase64: parsed.timestampResponseDerBase64,
    timestampRequestDerBase64: parsed.timestampRequestDerBase64,
    compactJwsBase64: parsed.compactJwsBase64,
    format: parsed.format,
  }, null, 2), 'utf8');
  assert.notEqual(sha256(serialized), sha256(rendered));
  for (const outerBytes of [serialized, rendered]) {
    const recovered = restoreSyntheticOuterEvidence(outerBytes);
    assert.deepEqual(recovered.compactJwsBytes(), artifact);
    assert.deepEqual(recovered.timestampRequestDerBytes(), request);
    assert.deepEqual(recovered.timestampResponseDerBytes(), response);
    assert.deepEqual(recovered.unverifiedLogArtifactBytes(), logArtifact);
    assert.deepEqual(recovered.fingerprints(), withLog.fingerprints());
    assert.equal(verifyTestResponse(recovered).status, 0);
  }
});

test('changed signature byte or valid JWS reserialization cannot inherit the first imprint', () => {
  const changed = Buffer.from(artifact);
  const offset = changed.lastIndexOf(0x2e) + 1;
  assert.equal(changed[offset], 0x42);
  changed[offset] = 0x41;
  const altered = freezeSyntheticOuterEvidence(changed, request)
    .withTimestampResponse(response);
  assert.notEqual(altered.fingerprints().compactJwsSha256, vector.compactJwsSha256);
  assert.notEqual(verifyTestResponse(altered).status, 0);
  const reserialized = freezeSyntheticOuterEvidence(
    Buffer.from(compact.reserializedCompactAscii, 'ascii'), request)
    .withTimestampResponse(response);
  assert.equal(reserialized.fingerprints().compactJwsSha256,
    vector.reserializedCompactJwsSha256);
  assert.notEqual(verifyTestResponse(reserialized).status, 0);
  changed[offset] = 0x42;
  assert.deepEqual(changed, artifact);
  assert.equal(verifyTestResponse(freezeSyntheticOuterEvidence(changed, request)
    .withTimestampResponse(response)).status, 0);
});

test('replacing only response bytes changes their fingerprint and requires revalidation', () => {
  const tampered = Buffer.from(timestamp.imprintBitflipResponseDerBase64, 'base64');
  const changed = base.withTimestampResponse(tampered);
  assert.equal(changed.fingerprints().compactJwsSha256,
    withResponse.fingerprints().compactJwsSha256);
  assert.equal(changed.fingerprints().timestampRequestDerSha256,
    withResponse.fingerprints().timestampRequestDerSha256);
  assert.equal(changed.fingerprints().timestampResponseDerSha256,
    vector.changedResponseDerSha256);
  assert.notEqual(changed.fingerprints().timestampResponseDerSha256,
    withResponse.fingerprints().timestampResponseDerSha256);
  assert.notEqual(verifyTestResponse(changed).status, 0);
});

test('changing only request imprint bytes fails request-token matching', () => {
  const changedRequest = Buffer.from(request);
  const digest = Buffer.from(compact.compactSha256, 'hex');
  const offset = changedRequest.indexOf(digest);
  assert.ok(offset > 0);
  assert.equal(changedRequest.lastIndexOf(digest), offset);
  changedRequest[offset] ^= 1;
  const changed = freezeSyntheticOuterEvidence(artifact, changedRequest)
    .withTimestampResponse(response);
  assert.equal(changed.fingerprints().compactJwsSha256,
    vector.compactJwsSha256);
  assert.equal(changed.fingerprints().timestampRequestDerSha256,
    vector.changedRequestDerSha256);
  assert.equal(changed.fingerprints().timestampResponseDerSha256,
    vector.timestampResponseDerSha256);
  assert.equal(verifyTestResponse(changed).status, 0); // response still matches artifact
  assert.notEqual(verifyTestResponse(changed, 'query').status, 0);
  changedRequest[offset] ^= 1;
  assert.deepEqual(changedRequest, request);
  assert.equal(verifyTestResponse(withResponse, 'query').status, 0);
});

test('changing only opaque log artifact bytes leaves the first edge unchanged', () => {
  const changedLog = withResponse.withUnverifiedLogArtifact(
    Buffer.from(vector.changedUnverifiedLogArtifactHex, 'hex'));
  assert.deepEqual(changedLog.compactJwsBytes(), withLog.compactJwsBytes());
  assert.deepEqual(changedLog.timestampRequestDerBytes(),
    withLog.timestampRequestDerBytes());
  assert.deepEqual(changedLog.timestampResponseDerBytes(),
    withLog.timestampResponseDerBytes());
  assert.equal(changedLog.fingerprints().unverifiedLogArtifactSha256,
    vector.changedUnverifiedLogArtifactSha256);
  assert.notEqual(changedLog.fingerprints().unverifiedLogArtifactSha256,
    withLog.fingerprints().unverifiedLogArtifactSha256);
  assert.equal(verifyTestResponse(changedLog).status, 0);
});

test('retained bytes are copied and evidence order is explicit', () => {
  const inputArtifact = Buffer.from(artifact);
  const inputRequest = Buffer.from(request);
  const inputResponse = Buffer.from(response);
  const inputLog = Buffer.from(logArtifact);
  const copiedAtEveryStage = freezeSyntheticOuterEvidence(inputArtifact, inputRequest)
    .withTimestampResponse(inputResponse).withUnverifiedLogArtifact(inputLog);
  for (const input of [inputArtifact, inputRequest, inputResponse, inputLog])
    input[0] ^= 1;
  assert.deepEqual(copiedAtEveryStage.compactJwsBytes(), artifact);
  assert.deepEqual(copiedAtEveryStage.timestampRequestDerBytes(), request);
  assert.deepEqual(copiedAtEveryStage.timestampResponseDerBytes(), response);
  assert.deepEqual(copiedAtEveryStage.unverifiedLogArtifactBytes(), logArtifact);
  const copiedArtifact = withLog.compactJwsBytes();
  const copiedResponse = withLog.timestampResponseDerBytes();
  const copiedLog = withLog.unverifiedLogArtifactBytes();
  copiedArtifact[0] ^= 1;
  copiedResponse[0] ^= 1;
  copiedLog[0] ^= 1;
  assert.deepEqual(withLog.compactJwsBytes(), artifact);
  assert.deepEqual(withLog.timestampResponseDerBytes(), response);
  assert.deepEqual(withLog.unverifiedLogArtifactBytes(), logArtifact);
  assert.throws(() => base.withUnverifiedLogArtifact(logArtifact), /Retain timestamp response first/);
  assert.throws(() => withResponse.withTimestampResponse(response), /already retained/);
  assert.throws(() => withLog.withUnverifiedLogArtifact(logArtifact), /already retained/);
});

test('returned byte fields have independent backing storage', () => {
  const copiedArtifact = withLog.compactJwsBytes();
  const copiedRequest = withLog.timestampRequestDerBytes();
  const copiedResponse = withLog.timestampResponseDerBytes();
  const copiedLog = withLog.unverifiedLogArtifactBytes();
  const copies = [copiedArtifact, copiedRequest, copiedResponse, copiedLog];
  for (const copy of copies) {
    assert.equal(copy.byteOffset, 0);
    assert.equal(copy.buffer.byteLength, copy.length);
  }
  assert.equal(new Set(copies.map(copy => copy.buffer)).size, copies.length);
  const before = withLog.fingerprints();
  for (const copy of copies) copy[0] ^= 1;
  assert.deepEqual(withLog.fingerprints(), before);
  const serialized = withLog.serializeBytes();
  const serializedAgain = withLog.serializeBytes();
  assert.equal(serialized.byteOffset, 0);
  assert.equal(serialized.buffer.byteLength, serialized.length);
  assert.notStrictEqual(serialized.buffer, serializedAgain.buffer);
  const beforeSerializationEdit = Buffer.from(serializedAgain);
  serialized[0] ^= 1;
  assert.deepEqual(withLog.serializeBytes(), beforeSerializationEdit);
});

test('duplicate decoded JSON member names are rejected in either order', () => {
  const original = withLog.serializeBytes().toString('utf8');
  const replacement = Buffer.from('changed frozen bytes').toString('base64');
  const alias = String.raw`"\u0063ompactJwsBase64"`;
  const originalField = `"compactJwsBase64":${JSON.stringify(artifact.toString('base64'))}`;
  const replacementField = `${alias}:${JSON.stringify(replacement)}`;
  for (const duplicate of [
    original.replace(originalField, `${originalField},${replacementField}`),
    original.replace(originalField, `${replacementField},${originalField}`),
  ]) {
    assert.throws(() => restoreSyntheticOuterEvidence(Buffer.from(duplicate, 'utf8')),
      /Duplicate outer record field/);
  }
});

test('malformed outer encoding does not silently alter retained bytes', () => {
  const original = JSON.parse(withLog.serializeBytes().toString('utf8'));
  for (const changed of [
    {...original, compactJwsBase64: `${original.compactJwsBase64}\n`},
    {...original, timestampResponseDerBase64: '!!!!'},
    {...original, extra: true},
    {...original, timestampResponseDerBase64: null},
  ]) {
    assert.throws(() => restoreSyntheticOuterEvidence(
      Buffer.from(JSON.stringify(changed), 'utf8')));
  }
  assert.throws(() => restoreSyntheticOuterEvidence(
    Buffer.concat([Buffer.from('efbbbf', 'hex'), withLog.serializeBytes()])), /BOM/);
});
