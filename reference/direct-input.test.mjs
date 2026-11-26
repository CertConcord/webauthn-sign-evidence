import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createPublicKey, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';

const vector = JSON.parse(readFileSync(new URL('../vectors/direct-input.json', import.meta.url), 'utf8'));
const bytes = hex => Buffer.from(hex, 'hex');
const publicKey = hex => createPublicKey({key: bytes(hex), format: 'der', type: 'spki'});
const signature = bytes(vector.signatureHex);
const selectedKey = publicKey(vector.publicKeySpkiDerHex);
const verifies = (tbsHex, key = selectedKey) => verify(null, bytes(tbsHex), key, signature);

test('exact original binary tbs verifies under the selected synthetic signing key', () => {
  const original = bytes(vector.tbsHex);
  assert.equal(original[0], 0x00);
  assert.equal(original[1], 0xff);
  assert.equal(createHash('sha256').update(original).digest('hex'), vector.tbsSha256);
  assert.equal(verifies(vector.tbsHex), true);
});

test('one changed tbs octet invalidates the same signature', () => {
  assert.equal(verifies(vector.changedTbsHex), false);
});

test('another signing key cannot validate the same signature', () => {
  assert.equal(verifies(vector.tbsHex, publicKey(vector.wrongPublicKeySpkiDerHex)), false);
});

test('substituting a digest for direct-input tbs invalidates the signature', () => {
  assert.equal(vector.prehashedTbsHex, vector.tbsSha256);
  assert.equal(verifies(vector.prehashedTbsHex), false);
});

test('UTF-8 decode and re-encode does not preserve this binary tbs', () => {
  const reconstructed = Buffer.from(bytes(vector.tbsHex).toString('utf8'), 'utf8');
  assert.notDeepEqual(reconstructed, bytes(vector.tbsHex));
  assert.equal(verify(null, reconstructed, selectedKey, signature), false);
});
