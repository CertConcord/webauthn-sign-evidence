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
const rfcExample = load('log-proof-rfc6962-example.json');
const policyVector = load('log-test-policy.json');
const inputBoundary = load('log-input-boundary.json');
const derivedBoundary = load('log-derived-input-boundary.json');
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
    keyIdHex: policyVector.keyIdHex,
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

test('RFC 6962 seven-leaf example paths bind three independently signed prior sizes', () => {
  const fromHex = value => Buffer.from(value, 'hex');
  const hash = value => fromHex(sha(value));
  const leaf = value => hash(Buffer.concat([Buffer.from([0]), value]));
  const node = (left, right) => hash(Buffer.concat([Buffer.from([1]), left, right]));
  const entryBundle = decode(rfcExample.entryBundleBase64);
  const entries = [];
  for (let offset = 0; offset < entryBundle.length;) {
    const length = entryBundle.readUInt16BE(offset);
    offset += 2;
    entries.push(entryBundle.subarray(offset, offset + length));
    offset += length;
  }
  assert.equal(entries.length, 7);
  assert.deepEqual(entries[6], syntheticJwsLogEntry(jws));
  assert.equal(sha(jws), rfcExample.jwsSha256);
  const [a, b, c, d, e, f, j] = entries.map(leaf);
  const g = node(a, b);
  const h = node(c, d);
  const i = node(e, f);
  const k = node(g, h);
  const l = node(i, j);
  const named = {a, b, c, d, e, f, g, h, i, j, k, l};
  assert.deepEqual(Object.fromEntries(Object.entries(named).map(([name, value]) =>
    [name, value.toString('hex')])), rfcExample.nodeHex);
  assert.deepEqual(rfcExample.rootHex, {
    '3': node(g, c).toString('hex'), '4': k.toString('hex'),
    '6': node(k, i).toString('hex'), '7': node(k, l).toString('hex'),
  });
  assert.deepEqual(rfcExample.inclusionPathHex, [i, k].map(value => value.toString('hex')));
  assert.deepEqual(decode(rfcExample.levelZeroTileBase64), Buffer.concat(entries.map(leaf)));
  assert.equal(rfcExample.privateKeyPublished, false);
  assert.equal(rfcExample.deployedLogEstablished, false);
  assert.equal(rfcExample.trustedTimeEstablished, false);

  const baseProof = {
    entryIndex: rfcExample.entryIndex,
    checkpointNoteBytes: decode(rfcExample.currentCheckpointBase64),
    entryBundleBytes: entryBundle,
    levelZeroTileBytes: decode(rfcExample.levelZeroTileBase64),
    inclusionPathHex: rfcExample.inclusionPathHex,
  };
  for (const previousSize of [3, 4, 6]) {
    const prior = rfcExample.prior[previousSize];
    assert.deepEqual(prior.consistencyPathHex,
      prior.rfcNodes.map(name => rfcExample.nodeHex[name]));
    const externalPolicy = {
      origin: rfcExample.origin, keyName: rfcExample.keyName,
      keyIdHex: rfcExample.keyIdHex, publicKeyRawHex: rfcExample.publicKeyRawHex,
      previousCheckpointNoteBytes: decode(prior.checkpointBase64),
    };
    const proofBytes = {...baseProof, consistencyPathHex: prior.consistencyPathHex};
    const checked = verifySyntheticTiledLogProof(jws, proofBytes, externalPolicy);
    assert.equal(checked.previousSize, previousSize);
    assert.equal(checked.currentSize, 7);
    assert.equal(checked.index, 6);
    const changed = [...prior.consistencyPathHex];
    changed[0] = (changed[0][0] === '0' ? '1' : '0') + changed[0].slice(1);
    assert.throws(() => verifySyntheticTiledLogProof(jws,
      {...proofBytes, consistencyPathHex: changed}, externalPolicy),
    /consistency proof failed/);
  }
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    {...baseProof, consistencyPathHex: rfcExample.prior['4'].consistencyPathHex},
    {origin: rfcExample.origin, keyName: rfcExample.keyName,
      keyIdHex: rfcExample.keyIdHex, publicKeyRawHex: rfcExample.publicKeyRawHex,
      previousCheckpointNoteBytes: decode(rfcExample.prior['3'].checkpointBase64)}),
  /consistency proof failed|Short consistency path/);
});

test('returned log entries cannot change another view or the versioned label', () => {
  const first = syntheticJwsLogEntry(jws);
  const second = syntheticJwsLogEntry(jws);
  assert.equal(first.length, 39);
  assert.equal(first.buffer.byteLength, first.length);
  assert.equal(second.buffer.byteLength, second.length);
  assert.notEqual(first.buffer, second.buffer);
  new Uint8Array(first.buffer).fill(0);
  assert.equal(second.toString('hex'), vector.entryHex);
  assert.equal(syntheticJwsLogEntry(jws).toString('hex'), vector.entryHex);
  assert.equal(verifySyntheticTiledLogProof(jws, proof(), policy()).leafSha256,
    vector.leafSha256);
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
  assert.equal(entries[0].length, 0);
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
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({checkpointNoteBytes: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]),
      original])}), policy()), /BOM/);
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
  assert.throws(() => verifySyntheticTiledLogProof(jws, proof(),
    policy({keyIdHex: 'deadbeef'})), /No trusted checkpoint signature/);
  const signatureLine = original.toString('utf8').split('\n').at(-2);
  const duplicateIdentity = Buffer.from(original.toString('utf8') +
    signatureLine + '\n', 'utf8');
  assert.throws(() => verifySyntheticTiledLogProof(jws,
    proof({checkpointNoteBytes: duplicateIdentity}), policy()),
    /Duplicate checkpoint signature identity/);
});

test('a separately configured nonrecommended signed-note key ID also verifies', () => {
  const alternate = policy({keyIdHex: vector.alternateKeyIdHex,
    previousCheckpointNoteBytes: decode(vector.alternatePreviousCheckpointBase64)});
  const result = verifySyntheticTiledLogProof(jws,
    proof({checkpointNoteBytes: decode(vector.alternateCurrentCheckpointBase64)}),
    alternate);
  assert.equal(result.leafSha256, vector.leafSha256);
});

test('both checkpoints use one fixed external log trust identity', () => {
  const previousCheckpointNoteBytes = decode(vector.alternatePreviousCheckpointBase64);
  const mixed = policy({previousCheckpointNoteBytes});
  assert.throws(() => verifySyntheticTiledLogProof(jws, proof(), mixed),
    /No trusted checkpoint signature/);
  assert.throws(() => verifySyntheticTiledLogProof(jws, proof(),
    policy({keyIdHex: vector.alternateKeyIdHex,
      previousCheckpointNoteBytes})), /No trusted checkpoint signature/);

  let keyIdReads = 0;
  Object.defineProperty(mixed, 'keyIdHex', {get() {
    return ++keyIdReads <= 3 ? policyVector.keyIdHex : vector.alternateKeyIdHex;
  }});
  assert.throws(() => verifySyntheticTiledLogProof(jws, proof(), mixed),
    /No trusted checkpoint signature/);
  assert.equal(keyIdReads, 1);

  const stable = policy();
  const reads = {};
  for (const name of ['origin', 'keyName', 'keyIdHex', 'publicKeyRawHex',
    'previousCheckpointNoteBytes']) {
    const value = stable[name];
    reads[name] = 0;
    Object.defineProperty(stable, name, {get() {
      reads[name] += 1;
      return value;
    }});
  }
  assert.equal(verifySyntheticTiledLogProof(jws, proof(), stable).currentSize,
    vector.currentSize);
  assert.deepEqual(reads, {
    origin: 1, keyName: 1, keyIdHex: 1, publicKeyRawHex: 1,
    previousCheckpointNoteBytes: 1,
  });
});

test('proof access cannot replace previously accepted checkpoint bytes', () => {
  const acceptedPrior = decode(policyVector.previousCheckpointBase64);
  const replacementPrior = decode(vector.alternatePreviousCheckpointBase64);
  assert.equal(acceptedPrior.length, replacementPrior.length);
  const independentPolicy = policy({keyIdHex: vector.alternateKeyIdHex,
    previousCheckpointNoteBytes: acceptedPrior});
  const hostileProof = proof();
  Object.defineProperty(hostileProof, 'checkpointNoteBytes', {get() {
    replacementPrior.copy(acceptedPrior);
    return decode(vector.alternateCurrentCheckpointBase64);
  }});
  assert.throws(() => verifySyntheticTiledLogProof(jws, hostileProof,
    independentPolicy), /No trusted checkpoint signature/);
  assert.deepEqual(acceptedPrior, replacementPrior);
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

test('signed size bounds bundle and tile before copying their input bytes', () => {
  const count = derivedBoundary.signedCheckpointSize;
  assert.equal(count, vector.currentSize);
  const maximum = count * (derivedBoundary.entryLengthPrefixBytes +
    derivedBoundary.maximumEntryBytes);
  assert.equal(maximum, derivedBoundary.bundleMaximumBytes);
  const fullBundle = Buffer.alloc(maximum);
  for (let offset = 0; offset < maximum; offset += 65537) {
    fullBundle.writeUInt16BE(65535, offset);
    fullBundle.fill(0x61, offset + 2, offset + 65537);
  }
  const oversizedBundle = Buffer.concat([fullBundle, Buffer.from([0])]);
  const fullTile = decode(vector.proof.levelZeroTileBase64);
  const oversizedTile = Buffer.concat([fullTile, Buffer.from([0])]);
  const shortTile = fullTile.subarray(0, fullTile.length - 1);
  assert.equal(fullTile.length, derivedBoundary.tileExpectedBytes);
  assert.equal(sha(fullBundle), derivedBoundary.bundleAtMaximumSha256);
  assert.equal(sha(oversizedBundle), derivedBoundary.bundleAdjacentOversizeSha256);
  assert.equal(sha(fullTile), derivedBoundary.tileAtExpectedSha256);
  assert.equal(sha(oversizedTile), derivedBoundary.tileAdjacentOversizeSha256);
  const nativeUint8Array = globalThis.Uint8Array;
  const nativeSet = nativeUint8Array.prototype.set;
  const nativeAlloc = Buffer.alloc;
  const viewPrototype = Object.getPrototypeOf(nativeUint8Array.prototype);
  const viewBuffer = Object.getOwnPropertyDescriptor(viewPrototype, 'buffer').get;
  const viewOffset = Object.getOwnPropertyDescriptor(viewPrototype, 'byteOffset').get;
  const viewLength = Object.getOwnPropertyDescriptor(viewPrototype, 'byteLength').get;
  let target;
  let source;
  let owned;
  let events;
  globalThis.Uint8Array = class extends nativeUint8Array {
    constructor(backing, ...args) {
      super(backing, ...args);
      if (target && backing === viewBuffer.call(target) &&
          args[0] === viewOffset.call(target) &&
          args[1] === viewLength.call(target)) {
        source = this;
        events.push('fixed source view');
      }
    }
  };
  Buffer.alloc = function(size, ...args) {
    const result = nativeAlloc.call(this, size, ...args);
    if (source && !owned && size === viewLength.call(target)) {
      owned = result;
      events.push('owned allocation');
    }
    return result;
  };
  nativeUint8Array.prototype.set = function(input, ...args) {
    if (this === owned && input === source) events.push('input copy');
    return nativeSet.call(this, input, ...args);
  };
  const check = (input, changes, expectedEvents, error) => {
    target = input;
    source = undefined;
    owned = undefined;
    events = [];
    const run = () => verifySyntheticTiledLogProof(jws, proof(changes), policy());
    if (error) assert.throws(run, error);
    else assert.equal(run().index, vector.proof.entryIndex);
    assert.deepEqual(events, expectedEvents);
  };
  const copied = ['fixed source view', 'owned allocation', 'input copy'];
  try {
    check(fullBundle, {entryBundleBytes: fullBundle}, copied, /Logged entry differs/);
    check(oversizedBundle, {entryBundleBytes: oversizedBundle}, [],
      /Entry bundle exceeds signed checkpoint size bound/);
    const emptyBundle = Buffer.alloc(0);
    check(emptyBundle, {entryBundleBytes: emptyBundle}, copied,
      /Entry count differs from checkpoint/);
    check(fullTile, {levelZeroTileBytes: fullTile}, copied);
    check(oversizedTile, {levelZeroTileBytes: oversizedTile}, [],
      /Level-zero partial tile has wrong width/);
    check(shortTile, {levelZeroTileBytes: shortTile}, [],
      /Level-zero partial tile has wrong width/);
  } finally {
    nativeUint8Array.prototype.set = nativeSet;
    Buffer.alloc = nativeAlloc;
    globalThis.Uint8Array = nativeUint8Array;
  }
});

test('local artifact and both checkpoint bounds reject before copying input bytes', () => {
  const limit = inputBoundary.maximumBytes;
  const admitted = Buffer.alloc(limit, Number.parseInt(inputBoundary.byteValueHex, 16));
  const tooLong = Buffer.alloc(inputBoundary.adjacentOversizeBytes,
    Number.parseInt(inputBoundary.byteValueHex, 16));
  assert.equal(sha(admitted), inputBoundary.atMaximumSha256);
  assert.equal(sha(tooLong), inputBoundary.adjacentOversizeSha256);
  const nativeUint8Array = globalThis.Uint8Array;
  const nativeSet = nativeUint8Array.prototype.set;
  const nativeBufferAlloc = Buffer.alloc;
  const nativeViewBuffer = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype), 'buffer').get;
  let target;
  let sourceView;
  let owned;
  let observations;
  globalThis.Uint8Array = class extends nativeUint8Array {
    constructor(value, ...args) {
      super(value, ...args);
      if (target && value === nativeViewBuffer.call(target)) {
        sourceView = this;
        observations.push('fixed source view');
      }
    }
  };
  Buffer.alloc = function(size, ...args) {
    const result = nativeBufferAlloc.call(this, size, ...args);
    if (sourceView && !owned && size === sourceView.length) {
      owned = result;
      observations.push('owned allocation');
    }
    return result;
  };
  nativeUint8Array.prototype.set = function(source, ...args) {
    if (this === owned && source === sourceView) observations.push('input copy');
    return nativeSet.call(this, source, ...args);
  };
  const check = (input, run, error, expected, proofReads) => {
    target = input;
    sourceView = undefined;
    owned = undefined;
    observations = [];
    assert.throws(run, error);
    assert.deepEqual(observations, expected);
    if (proofReads !== undefined) assert.equal(proofReads(), expected.includes('proof read') ? 1 : 0);
  };
  try {
    for (const [name, run, admittedError, rejectedError] of [
      ['artifact', input => () => restoreSyntheticLogProofArtifact(input),
        /Malformed synthetic log proof artifact/, /Log proof artifact is empty or too long/],
      ['current checkpoint', input => () => verifySyntheticTiledLogProof(jws,
        proof({checkpointNoteBytes: input}), policy()),
        /Malformed signed note/, /Checkpoint is empty or outside/],
      ['previous checkpoint', input => {
        let reads = 0;
        const inputProof = proof();
        Object.defineProperty(inputProof, 'checkpointNoteBytes', {get() {
          reads += 1;
          observations.push('proof read');
          return decode(vector.proof.checkpointNoteBase64);
        }});
        return {run: () => verifySyntheticTiledLogProof(jws, inputProof,
          policy({previousCheckpointNoteBytes: input})), reads: () => reads};
      }, /Malformed signed note/, /Checkpoint is empty or outside/],
    ]) {
      const admittedCall = run(admitted);
      const admittedRun = typeof admittedCall === 'function' ? admittedCall : admittedCall.run;
      const admittedReads = typeof admittedCall === 'function' ? undefined : admittedCall.reads;
      const admittedExpected = name === 'previous checkpoint'
        ? ['fixed source view', 'owned allocation', 'input copy', 'proof read']
        : ['fixed source view', 'owned allocation', 'input copy'];
      check(admitted, admittedRun, admittedError, admittedExpected, admittedReads);
      const rejectedCall = run(tooLong);
      check(tooLong, typeof rejectedCall === 'function' ? rejectedCall : rejectedCall.run,
        rejectedError, [], typeof rejectedCall === 'function' ? undefined : rejectedCall.reads);
      const spoofed = Buffer.alloc(limit + 1, 0x61);
      Object.defineProperties(spoofed, {
        length: {value: 1}, byteLength: {value: 1},
      });
      const spoofedCall = run(spoofed);
      check(spoofed, typeof spoofedCall === 'function' ? spoofedCall : spoofedCall.run,
        rejectedError, [], typeof spoofedCall === 'function' ? undefined : spoofedCall.reads);
      const empty = Buffer.alloc(0);
      const emptyCall = run(empty);
      check(empty, typeof emptyCall === 'function' ? emptyCall : emptyCall.run,
        rejectedError, [], typeof emptyCall === 'function' ? undefined : emptyCall.reads);
    }
  } finally {
    nativeUint8Array.prototype.set = nativeSet;
    Buffer.alloc = nativeBufferAlloc;
    globalThis.Uint8Array = nativeUint8Array;
  }
});

test('growing a length-tracking shared view cannot expand an admitted snapshot', () => {
  const limit = inputBoundary.maximumBytes;
  const nativeUint8Array = globalThis.Uint8Array;
  const nativeSet = nativeUint8Array.prototype.set;
  const nativeAlloc = Buffer.alloc;
  for (const [name, invoke, expectedError] of [
    ['artifact', input => () => restoreSyntheticLogProofArtifact(input),
      /Malformed synthetic log proof artifact/],
    ['current checkpoint', input => () => verifySyntheticTiledLogProof(jws,
      proof({checkpointNoteBytes: input}), policy()), /Malformed signed note/],
    ['previous checkpoint', input => () => verifySyntheticTiledLogProof(jws,
      proof(), policy({previousCheckpointNoteBytes: input})), /Malformed signed note/],
  ]) {
    const growth = inputBoundary.growableSharedView;
    const backing = new SharedArrayBuffer(growth.backingBytesBeforeCopy,
      {maxByteLength: growth.backingBytesAfterGrowth});
    const tracking = new Uint8Array(backing, growth.byteOffset);
    tracking.fill(0x61);
    assert.equal(tracking.byteLength, growth.admittedViewBytes);
    assert.equal(sha(tracking), growth.admittedContentSha256);
    const run = invoke(tracking);
    const seen = {name};
    globalThis.Uint8Array = class extends nativeUint8Array {
      constructor(value, ...args) {
        super(value, ...args);
        if (value !== backing) return;
        seen.source = this;
        seen.sourceOffset = args[0];
        seen.sourceLength = args[1];
      }
    };
    Buffer.alloc = function(size, ...args) {
      if (seen.source && !seen.grew && size === limit) {
        backing.grow(growth.backingBytesAfterGrowth);
        seen.grew = true;
      }
      const result = nativeAlloc.call(this, size, ...args);
      if (seen.grew && !seen.owned && size === limit) seen.owned = result;
      return result;
    };
    nativeUint8Array.prototype.set = function(source, ...args) {
      if (this === seen.owned && source === seen.source) {
        seen.copied = source.byteLength;
        seen.firstByte = source[0];
        seen.lastByte = source[source.length - 1];
      }
      return nativeSet.call(this, source, ...args);
    };
    try {
      assert.throws(run, expectedError);
      assert.equal(backing.byteLength, growth.backingBytesAfterGrowth);
      assert.deepEqual({offset: seen.sourceOffset, source: seen.sourceLength,
        owned: seen.owned?.length, copied: seen.copied,
        first: seen.firstByte, last: seen.lastByte,
        ownedFirst: seen.owned?.[0], ownedLast: seen.owned?.[limit - 1]},
      {offset: growth.byteOffset, source: growth.expectedSourceAndOwnedBytes,
        owned: growth.expectedSourceAndOwnedBytes,
        copied: growth.expectedSourceAndOwnedBytes,
        first: 0x61, last: 0x61, ownedFirst: 0x61, ownedLast: 0x61});
    } finally {
      nativeUint8Array.prototype.set = nativeSet;
      Buffer.alloc = nativeAlloc;
      globalThis.Uint8Array = nativeUint8Array;
    }
  }
});

test('shadowed backing length cannot reject a genuine offset byte view', () => {
  const current = decode(vector.proof.checkpointNoteBase64);
  const previous = decode(policyVector.previousCheckpointBase64);
  for (const Backing of [ArrayBuffer, SharedArrayBuffer]) {
    for (const [name, original, run] of [
      ['artifact', proofArtifact, input =>
        restoreSyntheticLogProofArtifact(input).entryIndex],
      ['current checkpoint', current, input =>
        verifySyntheticTiledLogProof(jws,
          proof({checkpointNoteBytes: input}), policy()).index],
      ['previous checkpoint', previous, input =>
        verifySyntheticTiledLogProof(jws, proof(),
          policy({previousCheckpointNoteBytes: input})).index],
    ]) {
      const backing = new Backing(original.length + 16);
      const view = new Uint8Array(backing, 8, original.length);
      view.set(original);
      let publicLengthReads = 0;
      Object.defineProperty(backing, 'byteLength', {get() {
        publicLengthReads += 1;
        throw new Error('PUBLIC_BACKING_LENGTH_READ');
      }});
      assert.equal(run(view), vector.entryIndex, name);
      assert.equal(publicLengthReads, 0, name);
    }
  }
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
  const parsed = JSON.parse(raw);
  const reordered = {entryIndex: parsed.entryIndex, format: parsed.format,
    checkpointNoteBase64: parsed.checkpointNoteBase64,
    entryBundleBase64: parsed.entryBundleBase64,
    levelZeroTileBase64: parsed.levelZeroTileBase64,
    inclusionPathHex: parsed.inclusionPathHex,
    consistencyPathHex: parsed.consistencyPathHex};
  assert.throws(() => restoreSyntheticLogProofArtifact(
    Buffer.from(JSON.stringify(reordered), 'utf8')), /Noncanonical/);
  assert.throws(() => restoreSyntheticLogProofArtifact(
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), proofArtifact])), /Malformed/);
});

test('restored log fields have exact backing separate from other fields and calls', () => {
  const names = ['checkpointNoteBytes', 'entryBundleBytes', 'levelZeroTileBytes'];
  for (const changed of names) {
    const first = restoreSyntheticLogProofArtifact(proofArtifact);
    const second = restoreSyntheticLogProofArtifact(proofArtifact);
    const fields = [first, second].flatMap(value => names.map(name => value[name]));
    for (const field of fields) {
      assert.equal(field.buffer.byteLength, field.byteLength);
      assert.notEqual(field.buffer, proofArtifact.buffer);
    }
    assert.equal(new Set(fields.map(field => field.buffer)).size, fields.length);
    const originals = names.map(name => Buffer.from(first[name]));
    new Uint8Array(first[changed].buffer).fill(0);
    for (const [index, name] of names.entries()) {
      if (name !== changed) assert.deepEqual(first[name], originals[index]);
      assert.deepEqual(second[name], originals[index]);
    }
    assert.equal(verifySyntheticTiledLogProof(jws, second, policy()).leafSha256,
      vector.leafSha256);
  }
});

test('entry index is frozen once before bundle, path and result checks', () => {
  const withGetter = proof();
  let reads = 0;
  Object.defineProperty(withGetter, 'entryIndex', {get() {
    reads++;
    return reads === 1 ? vector.entryIndex : 1;
  }});
  assert.equal(verifySyntheticTiledLogProof(jws, withGetter, policy()).index,
    vector.entryIndex);
  assert.equal(reads, 1);
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
