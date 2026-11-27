import {createHash, createPublicKey, verify} from 'node:crypto';
import {types} from 'node:util';

const utf8 = new TextDecoder('utf-8', {fatal: true});
const label = Buffer.alloc(7);
label.write('CCWSL1\0', 'ascii');
const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const artifactFormat = 'synthetic-one-partial-tile-proof-v1';
const artifactKeys = ['format', 'entryIndex', 'checkpointNoteBase64',
  'entryBundleBase64', 'levelZeroTileBase64', 'inclusionPathHex',
  'consistencyPathHex'];
const localInputBound = 131072;
const byteViewPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const nativeByteLength = Object.getOwnPropertyDescriptor(
  byteViewPrototype, 'byteLength').get;
const nativeByteOffset = Object.getOwnPropertyDescriptor(
  byteViewPrototype, 'byteOffset').get;
const nativeBuffer = Object.getOwnPropertyDescriptor(
  byteViewPrototype, 'buffer').get;
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const nodeHash = (left, right) => sha256(Buffer.concat([Buffer.from([1]), left, right]));
const leafHash = entry => sha256(Buffer.concat([Buffer.from([0]), entry]));

function bytes(value, name, boundError) {
  if (!types.isUint8Array(value)) throw new TypeError(name + ' must be native bytes');
  if (!boundError) return Buffer.from(new Uint8Array(value).buffer);
  const offset = nativeByteOffset.call(value);
  const backing = nativeBuffer.call(value);
  const length = nativeByteLength.call(value);
  if (length === 0 || length > localInputBound) throw new TypeError(boundError);
  // Keep both the source view and owned destination at the admitted extent.
  // A length-tracking view may grow after the intrinsic length check.
  const source = Buffer.from(backing, offset, length);
  const owned = Buffer.alloc(length);
  if (source.copy(owned) !== length)
    throw new TypeError(name + ' changed during snapshot copy');
  return owned;
}

function hex32(value, name) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))
    throw new TypeError(name + ' must be a 32-byte lowercase hex hash');
  return Buffer.from(value, 'hex');
}

function canonicalBase64(value, name) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    throw new TypeError(name + ' must be canonical base64');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value)
    throw new TypeError(name + ' must be canonical base64');
  return bytes(decoded, name);
}

function largestPowerBelow(n) {
  let power = 1;
  while (power * 2 < n) power *= 2;
  return power;
}

function merkleRoot(hashes) {
  if (hashes.length === 1) return hashes[0];
  const split = largestPowerBelow(hashes.length);
  return nodeHash(merkleRoot(hashes.slice(0, split)),
    merkleRoot(hashes.slice(split)));
}

function auditRoot(leaf, index, size, pathHex) {
  if (!Array.isArray(pathHex)) throw new TypeError('Inclusion path must be an array');
  const path = pathHex.map((value, i) => hex32(value, `inclusion node ${i}`));
  let cursor = 0;
  const visit = (hash, i, n) => {
    if (n === 1) return hash;
    const split = largestPowerBelow(n);
    if (i < split) {
      const left = visit(hash, i, split);
      if (cursor >= path.length) throw new TypeError('Short inclusion path');
      return nodeHash(left, path[cursor++]);
    }
    const right = visit(hash, i - split, n - split);
    if (cursor >= path.length) throw new TypeError('Short inclusion path');
    return nodeHash(path[cursor++], right);
  };
  const root = visit(leaf, index, size);
  if (cursor !== path.length) throw new TypeError('Long inclusion path');
  return root;
}

function consistencyRoots(oldRoot, oldSize, newSize, pathHex) {
  if (!Array.isArray(pathHex)) throw new TypeError('Consistency path must be an array');
  const path = pathHex.map((value, i) => hex32(value, `consistency node ${i}`));
  let cursor = 0;
  const next = () => {
    if (cursor >= path.length) throw new TypeError('Short consistency path');
    return path[cursor++];
  };
  // Reconstruct both roots from RFC 6962 SUBPROOF(m, D[n], b).
  const visit = (m, n, known) => {
    if (m === n) {
      const root = known ? oldRoot : next();
      return {old: root, current: root};
    }
    const split = largestPowerBelow(n);
    if (m <= split) {
      const left = visit(m, split, known);
      return {old: left.old, current: nodeHash(left.current, next())};
    }
    const right = visit(m - split, n - split, false);
    const left = next();
    return {old: nodeHash(left, right.old),
      current: nodeHash(left, right.current)};
  };
  const roots = visit(oldSize, newSize, true);
  if (cursor !== path.length) throw new TypeError('Long consistency path');
  return roots;
}

function signedCheckpoint(rawBytes, trust) {
  const source = bytes(rawBytes, 'checkpoint',
    'Checkpoint is empty or outside the synthetic size bound');
  if (source.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])))
    throw new TypeError('Signed checkpoint BOM is not accepted');
  const raw = utf8.decode(source);
  if (/[\x00-\x09\x0b-\x1f]/.test(raw))
    throw new TypeError('Checkpoint contains a forbidden control character');
  const split = raw.lastIndexOf('\n\n');
  if (split < 0 || !raw.endsWith('\n'))
    throw new TypeError('Malformed signed note');
  const noteText = raw.slice(0, split + 1);
  const byteSplit = source.lastIndexOf(Buffer.from('\n\n', 'ascii'));
  if (byteSplit < 0) throw new TypeError('Malformed signed note bytes');
  const noteTextBytes = source.subarray(0, byteSplit + 1);
  if (utf8.decode(noteTextBytes) !== noteText)
    throw new TypeError('Signed note text differs from original bytes');
  const signatures = raw.slice(split + 2, -1).split('\n');
  if (signatures.length < 1 || signatures.length > 16)
    throw new TypeError('Unexpected number of note signatures');
  const lines = noteText.slice(0, -1).split('\n');
  if (lines.length < 3 || lines.some(line => line.length === 0))
    throw new TypeError('Malformed checkpoint text');
  const [origin, sizeText, rootText] = lines;
  if (origin !== trust.origin) throw new TypeError('Unexpected checkpoint origin');
  if (!/^(?:0|[1-9][0-9]*)$/.test(sizeText))
    throw new TypeError('Noncanonical checkpoint size');
  const size = Number(sizeText);
  if (!Number.isSafeInteger(size) || size < 1 || size > 255)
    throw new TypeError('Checkpoint exceeds the one-partial-tile scope');
  const root = canonicalBase64(rootText, 'checkpoint root');
  if (root.length !== 32) throw new TypeError('Checkpoint root must be 32 bytes');
  const publicKey = hex32(trust.publicKeyRawHex, 'trusted log public key');
  // Signed Note recommends deriving IDs; it does not require that derivation.
  if (typeof trust.keyIdHex !== 'string' || !/^[0-9a-f]{8}$/.test(trust.keyIdHex))
    throw new TypeError('Trusted log key ID must be four lowercase hex bytes');
  const keyId = Buffer.from(trust.keyIdHex, 'hex');
  const key = createPublicKey({key: Buffer.concat([spkiPrefix, publicKey]),
    format: 'der', type: 'spki'});
  let matched = false;
  const seenSignatures = new Set();
  for (const line of signatures) {
    const match = /^— ([^\s+]+) ([A-Za-z0-9+/]+={0,2})$/.exec(line);
    if (!match) throw new TypeError('Malformed signed-note signature line');
    const signature = canonicalBase64(match[2], 'note signature');
    if (signature.length < 4) throw new TypeError('Short note signature');
    const identity = JSON.stringify([match[1], signature.subarray(0, 4).toString('hex')]);
    if (seenSignatures.has(identity))
      throw new TypeError('Duplicate checkpoint signature identity');
    seenSignatures.add(identity);
    if (match[1] !== trust.keyName || !signature.subarray(0, 4).equals(keyId))
      continue;
    if (signature.length !== 68 || !verify(null, noteTextBytes,
      key, signature.subarray(4)))
      throw new TypeError('Invalid trusted checkpoint signature');
    matched = true;
  }
  if (!matched) throw new TypeError('No trusted checkpoint signature');
  return {size, root, noteSha256: sha256(source).toString('hex')};
}

function bundleEntries(bundleBytes, count) {
  const source = bytes(bundleBytes, 'entry bundle');
  const entries = [];
  let offset = 0;
  while (offset < source.length) {
    if (source.length - offset < 2) throw new TypeError('Truncated entry length');
    const length = source.readUInt16BE(offset);
    offset += 2;
    if (length > source.length - offset)
      throw new TypeError('Truncated log entry');
    entries.push(source.subarray(offset, offset + length));
    offset += length;
  }
  if (entries.length !== count) throw new TypeError('Entry count differs from checkpoint');
  return entries;
}

export function syntheticJwsLogEntry(jwsBytes) {
  const jws = bytes(jwsBytes, 'complete compact JWS');
  if (jws.length === 0 || !jws.every(value => value < 0x80))
    throw new TypeError('Complete compact JWS must be nonempty ASCII bytes');
  return bytes(Buffer.concat([label, sha256(jws)]), 'synthetic log entry');
}

// This narrow JSON encoding is byte-canonical within the synthetic fixture.
// The re-encoding check rejects duplicate names before they can affect a claim.
export function restoreSyntheticLogProofArtifact(artifactBytes) {
  const source = bytes(artifactBytes, 'log proof artifact',
    'Log proof artifact is empty or too long');
  if (source.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])))
    throw new TypeError('Malformed synthetic log proof artifact BOM');
  const raw = utf8.decode(source);
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new TypeError('Malformed synthetic log proof artifact');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      JSON.stringify(value) !== raw ||
      JSON.stringify(Object.keys(value)) !== JSON.stringify(artifactKeys) ||
      value.format !== artifactFormat ||
      !Number.isSafeInteger(value.entryIndex) || value.entryIndex < 0 ||
      !Array.isArray(value.inclusionPathHex) ||
      !Array.isArray(value.consistencyPathHex))
    throw new TypeError('Noncanonical synthetic log proof artifact');
  return {
    entryIndex: value.entryIndex,
    checkpointNoteBytes: canonicalBase64(value.checkpointNoteBase64, 'checkpoint'),
    entryBundleBytes: canonicalBase64(value.entryBundleBase64, 'entry bundle'),
    levelZeroTileBytes: canonicalBase64(value.levelZeroTileBase64, 'level-zero tile'),
    inclusionPathHex: value.inclusionPathHex.map((item, i) =>
      hex32(item, `inclusion node ${i}`).toString('hex')),
    consistencyPathHex: value.consistencyPathHex.map((item, i) =>
      hex32(item, `consistency node ${i}`).toString('hex')),
  };
}

// Offline one-partial-tile verification only. Trust comes solely from policy.
// The caller must validate policy.origin against C2SP Checkpoints v1.1.0 origin
// syntax before this call; this sample checks only its exact signed equality.
export function verifySyntheticTiledLogProof(jwsBytes, proof, policy) {
  if (proof === null || typeof proof !== 'object' ||
      policy === null || typeof policy !== 'object')
    throw new TypeError('Proof and independent log policy are required');
  // Own the accepted prior bytes before any proof accessor can run.
  const previousCheckpointNoteBytes = bytes(
    policy.previousCheckpointNoteBytes, 'previous checkpoint',
    'Checkpoint is empty or outside the synthetic size bound');
  // Use one trust identity for the current and previously accepted checkpoint.
  const trust = {
    origin: policy.origin,
    keyName: policy.keyName,
    keyIdHex: policy.keyIdHex,
    publicKeyRawHex: policy.publicKeyRawHex,
    previousCheckpointNoteBytes,
  };
  if (typeof trust.origin !== 'string' || typeof trust.keyName !== 'string')
    throw new TypeError('Proof and independent log policy are required');
  const expectedEntry = syntheticJwsLogEntry(jwsBytes);
  const index = proof.entryIndex;
  const current = signedCheckpoint(proof.checkpointNoteBytes, trust);
  const previous = signedCheckpoint(trust.previousCheckpointNoteBytes, trust);
  if (!(previous.size < current.size))
    throw new TypeError('Previous checkpoint must precede current checkpoint');
  if (!Number.isSafeInteger(index) || index < 0 || index >= current.size)
    throw new TypeError('Log entry index is outside the signed tree');
  const entries = bundleEntries(proof.entryBundleBytes, current.size);
  if (!entries[index].equals(expectedEntry))
    throw new TypeError('Logged entry differs from the complete JWS digest entry');
  const tile = bytes(proof.levelZeroTileBytes, 'level-zero tile');
  if (tile.length !== 32 * current.size)
    throw new TypeError('Level-zero partial tile has wrong width');
  const hashes = entries.map((entry, index) => {
    const hash = leafHash(entry);
    if (!hash.equals(tile.subarray(index * 32, (index + 1) * 32)))
      throw new TypeError('Entry bundle and level-zero tile disagree');
    return hash;
  });
  if (!merkleRoot(hashes).equals(current.root))
    throw new TypeError('Tile does not reconstruct signed checkpoint root');
  if (!auditRoot(hashes[index], index, current.size,
    proof.inclusionPathHex).equals(current.root))
    throw new TypeError('Inclusion path does not reach signed checkpoint root');
  const consistency = consistencyRoots(previous.root, previous.size,
    current.size, proof.consistencyPathHex);
  if (!consistency.old.equals(previous.root) ||
      !consistency.current.equals(current.root))
    throw new TypeError('Checkpoint consistency proof failed');
  return Object.freeze({
    entrySha256: sha256(expectedEntry).toString('hex'),
    leafSha256: hashes[index].toString('hex'),
    previousSize: previous.size,
    currentSize: current.size,
    index,
    previousCheckpointSha256: previous.noteSha256,
    checkpointSha256: current.noteSha256,
  });
}
