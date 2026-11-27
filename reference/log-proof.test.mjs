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
import {restoreSyntheticLogProofArtifact, syntheticJwsLogEntry,
  verifySyntheticTiledLogProof} from './log-proof.mjs';

const load = name => JSON.parse(readFileSync(new URL('../vectors/' + name, import.meta.url), 'utf8'));
const jwsVector = load('optional-jws.json');
const firstVector = load('optional-jws-response.json');
const laterVector = load('later-timestamp.json');
const vector = load('log-proof.json');
const policyVector = load('log-test-policy.json');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const decode = value => Buffer.from(value, 'base64');
const jws = Buffer.from(jwsVector.compactAscii, 'ascii');
const request1 = Buffer.from(jwsVector.timestampRequestDerHex, 'hex');
const response1 = decode(firstVector.positiveResponseDerBase64);
const proofArtifact = decode(vector.proofArtifactBase64);
const snapshot = decode(vector.newFrozenOuterSnapshotBase64);
const request2 = decode(vector.secondRequestDerBase64);
const response2 = decode(vector.secondResponseDerBase64);

function proof(overrides = {}) {
  return {
    entryIndex: vector.proof.entryIndex,
    checkpointNoteBytes: decode(vector.proof.checkpointNoteBase64),
    entryBundleBytes: decode(vector.proof.entryBundleBase64),
    levelZeroTileBytes: decode(vector.proof.levelZeroTileBase64),
    inclusionPathHex: [...vector.proof.inclusionPathHex],
    consistencyPathHex: [...vector.proof.consistencyPathHex],
    ...overrides,
  };
}

function policy(overrides = {}) {
  return {
    origin: policyVector.origin,
    keyName: policyVector.keyName,
    publicKeyRawHex: policyVector.publicKeyRawHex,
    previousCheckpointNoteBytes: decode(policyVector.previousCheckpointBase64),
    ...overrides,
  };
}

function verifyResponse(data, request, response, mode) {
  const dir = mkdtempSync(join(tmpdir(), 'webauthn-log-ts-'));
  try {
    const dataPath = join(dir, 'data.bin');
    const requestPath = join(dir, 'request.der');
    const responsePath = join(dir, 'response.der');
    const rootPath = join(dir, 'root.pem');
    writeFileSync(dataPath, data);
    writeFileSync(requestPath, request);
    writeFileSync(responsePath, response);
    writeFileSync(rootPath, firstVector.testRootPem);
    const target = mode === 'query' ? ['-queryfile', requestPath] : ['-data', dataPath];
    const result = spawnSync('openssl', ['ts', '-verify', ...target, '-in', responsePath,
      '-CAfile', rootPath, '-attime', String(vector.fixedVerificationEpochSeconds)], {
      encoding: 'utf8', timeout: 15_000,
    });
    if (result.error) throw result.error;
    return result.status;
  } finally {
    rmSync(dir, {recursive: true, force: true});
  }
}

function changedByte(bytes, position = 0) {
  const changed = Buffer.from(bytes);
  changed[position] ^= 1;
  return changed;
}

test('exact JWS digest entry binds to a trusted test-key checkpoint and prior tree', () => {
  const entry = syntheticJwsLogEntry(jws);
  assert.equal(entry.length, 39);
  assert.equal(entry.toString('hex'), vector.entryHex);
  assert.equal(sha(jws), vector.jwsSha256);
  assert.equal(sha(entry), vector.entrySha256);
  const checked = verifySyntheticTiledLogProof(jws, proof(), policy());
  assert.equal(checked.leafSha256, vector.leafSha256);
  assert.equal(checked.previousSize, vector.previousSize);
  assert.equal(checked.currentSize, vector.currentSize);
  assert.equal(checked.index, vector.entryIndex);
  assert.equal(vector.claims.deployedLog, false);
  assert.equal(vector.claims.trustedLogKeyEstablished, false);
  assert.equal(vector.claims.logWitnessOrMonitorEstablished, false);
});

test('bundle and tile expose the exact entry at its signed index', () => {
  const bundle = decode(vector.proof.entryBundleBase64);
  const tile = decode(vector.proof.levelZeroTileBase64);
  assert.equal(tile.length, 32 * vector.currentSize);
  let offset = 0;
  const entries = [];
  while (offset < bundle.length) {
    const length = bundle.readUInt16BE(offset);
    offset += 2;
    entries.push(bundle.subarray(offset, offset + length));
    offset += length;
  }
  assert.equal(entries.length, vector.currentSize);
  assert.deepEqual(entries[vector.entryIndex], Buffer.from(vector.entryHex, 'hex'));
  assert.equal(sha(Buffer.concat([Buffer.from([0]), entries[vector.entryIndex]])),
    vector.leafSha256);
});

test('changed JWS, entry and index cannot inherit the inclusion claim', () => {
  const changedJws = Buffer.from(jws);
  changedJws[changedJws.lastIndexOf(0x2e) + 1] ^= 1;
  assert.throws(() => verifySyntheticTiledLogProof(changedJws, proof(), policy()),
    /Logged entry differs/);
  const changedBundle = decode(vector.proof.entryBundleBase64);
  const entryPosition = changedBundle.indexOf(Buffer.from(vector.entryHex, 'hex'));
  assert(entryPosition >= 0);
  changedBundle[entryPosition + 7] ^= 1;
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({entryBundleBytes: changedBundle}), policy()), /Logged entry differs/);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({entryIndex: 1}), policy()), /Logged entry differs/);
});

test('inclusion path, tile and bundle framing are checked independently', () => {
  const changedPath = [...vector.proof.inclusionPathHex];
  changedPath[0] = (changedPath[0][0] === '0' ? '1' : '0') + changedPath[0].slice(1);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({inclusionPathHex: changedPath}), policy()), /Inclusion path/);
  const changedTile = changedByte(decode(vector.proof.levelZeroTileBase64), 0);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({levelZeroTileBytes: changedTile}), policy()), /tile disagree/);
  const changedBundle = changedByte(decode(vector.proof.entryBundleBase64), 0);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({entryBundleBytes: changedBundle}), policy()), /Truncated/);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({inclusionPathHex: [...vector.proof.inclusionPathHex].reverse()}), policy()),
    /Inclusion path/);
});

test('checkpoint origin, root, signature and self-supplied key cannot set trust', () => {
  const original = decode(vector.proof.checkpointNoteBase64);
  const changedOrigin = Buffer.from(original.toString('utf8').replace(
    policyVector.origin, 'example.invalid/forged-log'), 'utf8');
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({checkpointNoteBytes: changedOrigin}), policy()), /origin/);
  // The root is encoded in base64, so mutating a byte in its text is explicit.
  const lines = original.toString('utf8').split('\n');
  lines[2] = (lines[2][0] === 'A' ? 'B' : 'A') + lines[2].slice(1);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({checkpointNoteBytes: Buffer.from(lines.join('\n'), 'utf8')}), policy()),
    /signature/);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({checkpointNoteBytes: decode(vector.differentSignedCurrentCheckpointBase64)}),
    policy()), /Tile does not reconstruct/);
  const signatureChanged = changedByte(original, original.length - 3);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({checkpointNoteBytes: signatureChanged}), policy()), /signature|base64/);
  const selfSigned = decode(vector.selfSignedCheckpointBase64);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({checkpointNoteBytes: selfSigned,
      selfSuppliedPublicKeyRawHex: vector.selfSuppliedPublicKeyRawHex}), policy()),
    /No trusted checkpoint signature/);
});

test('only a separately accepted old checkpoint can establish append-only continuity', () => {
  const inconsistent = decode(vector.inconsistentPreviousCheckpointBase64);
  assert.throws(() => verifySyntheticTiledLogProof(jws, proof(),
    policy({previousCheckpointNoteBytes: inconsistent})), /consistency proof failed/);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({consistencyPathHex: [...vector.proof.consistencyPathHex].reverse()}),
    policy()), /consistency proof failed/);
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({consistencyPathHex: vector.proof.consistencyPathHex.slice(0, -1)}),
    policy()), /Short consistency path/);
});

test('raw log artifact restores the original proof without JSON field collapse', () => {
  const restored = restoreSyntheticLogProofArtifact(proofArtifact);
  assert.deepEqual(restored, proof());
  assert.equal(verifySyntheticTiledLogProof(jws, restored, policy()).index,
    vector.entryIndex);
  const raw = proofArtifact.toString('utf8');
  const duplicate = raw.replace('"entryIndex":2', '"entryIndex":1,"entryIndex":2');
  assert.notEqual(duplicate, raw);
  assert.throws(() => restoreSyntheticLogProofArtifact(Buffer.from(duplicate, 'utf8')),
    /Noncanonical/);
  assert.throws(() => restoreSyntheticLogProofArtifact(
    Buffer.from(JSON.stringify(JSON.parse(raw), null, 2), 'utf8')), /Noncanonical/);
  assert.throws(() => restoreSyntheticLogProofArtifact(
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), proofArtifact])), /Malformed/);
});

test('verified synthetic log bytes can be retained outside JWS before a new second target', () => {
  assert.deepEqual(proofArtifact, Buffer.from(JSON.stringify(vector.proof), 'utf8'));
  assert.equal(sha(proofArtifact), vector.proofArtifactSha256);
  const outer = freezeSyntheticOuterEvidence(jws, request1)
    .withTimestampResponse(response1).withUnverifiedLogArtifact(proofArtifact);
  assert.deepEqual(outer.serializeBytes(), snapshot);
  const restoredOuter = restoreSyntheticOuterEvidence(snapshot);
  assert.deepEqual(restoredOuter.unverifiedLogArtifactBytes(), proofArtifact);
  assert.equal(verifySyntheticTiledLogProof(jws,
    restoreSyntheticLogProofArtifact(restoredOuter.unverifiedLogArtifactBytes()),
    policy()).index, vector.entryIndex);
  assert.equal(snapshot.length, vector.newFrozenOuterSnapshotLength);
  assert.equal(sha(snapshot), vector.newFrozenOuterSnapshotSha256);
  assert.notEqual(sha(snapshot), laterVector.frozenOuterSnapshotSha256);
  assert.equal(outer.fingerprints().compactJwsSha256, laterVector.firstCompleteJwsSha256);
  assert.equal(verifyResponse(jws, request1, response1, 'data'), 0);
  assert.equal(verifyResponse(jws, request1, response1, 'query'), 0);
  const complete = freezeSyntheticLaterTimestampTarget(snapshot)
    .withLaterRequestDer(request2).withLaterResponseDer(response2);
  const restored = restoreSyntheticLaterTimestampRecord(complete.serializeBytes());
  assert.deepEqual(restored.targetSnapshotBytes(), snapshot);
  assert.deepEqual(restored.laterRequestDerBytes(), request2);
  assert.deepEqual(restored.laterResponseDerBytes(), response2);
  assert.equal(sha(complete.serializeBytes()), vector.recordSha256);
  assert.equal(verifyResponse(snapshot, request2, response2, 'data'), 0);
  assert.equal(verifyResponse(snapshot, request2, response2, 'query'), 0);
  assert.notEqual(verifyResponse(snapshot,
    decode(laterVector.laterRequestDerBase64),
    decode(laterVector.laterResponseDerBase64), 'data'), 0);
  const changedLog = changedByte(proofArtifact);
  const changedSnapshot = freezeSyntheticOuterEvidence(jws, request1)
    .withTimestampResponse(response1).withUnverifiedLogArtifact(changedLog)
    .serializeBytes();
  assert.equal(verifyResponse(jws, request1, response1, 'data'), 0);
  assert.notEqual(verifyResponse(changedSnapshot, request2, response2, 'data'), 0);
});
