import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const json = path => JSON.parse(readFileSync(join(root, path), 'utf8'));
const draft = json('draft.json');
assert.equal(draft.stable, false);
assert.equal(draft.w3cExtensionAdopted, false);
assert.equal(draft.authenticatorImplementationDemonstrated, false);
assert.equal(json('package.json').private, true);

const cases = json('cases.json').cases;
assert.equal(new Set(cases.map(item => item.id)).size, cases.length);
for (const source of json('sources.json').sources) {
  assert(source.url.startsWith('https://github.com/'));
  if (source.sha256) {
    assert.match(source.sha256, /^[a-f0-9]{64}$/);
    assert.match(source.commit, /^[a-f0-9]{40}$/);
    assert(Number.isSafeInteger(source.bytes) && source.bytes > 0);
  }
}
const relatedIetfDrafts = json('sources.json').relatedIetfDrafts;
assert.deepEqual(relatedIetfDrafts.map(item => item.id), [
  'citedCoseTwoPartyIndividual01', 'coseSplitSigningWg01Comparison',
]);
for (const source of relatedIetfDrafts) {
  assert.match(source.url, /^https:\/\/www\.ietf\.org\/archive\/id\/draft-[a-z0-9-]+-01\.txt$/);
  assert.match(source.sha256, /^[a-f0-9]{64}$/);
  assert(Number.isSafeInteger(source.bytes) && source.bytes > 0);
  assert.equal(typeof source.role, 'string');
}
const argsFraming = json('vectors/source-v6-args-framing.json');
assert.equal(argsFraming.source.citedCoseIndividual01Sha256,
  relatedIetfDrafts[0].sha256);
assert.equal(argsFraming.source.laterCoseWg01Sha256,
  relatedIetfDrafts[1].sha256);
const precopy = json('vectors/source-v6-cbor-precopy.json');
assert.equal(precopy.maxRequestBytes, 1 + 3 * (1 + 3 + precopy.fieldContentBytes) + 2);
assert.equal(precopy.overLimitBytes, precopy.maxRequestBytes + 1);
for (const digest of [precopy.maxRequestSha256, precopy.overLimitSha256])
  assert.match(digest, /^[a-f0-9]{64}$/);

const vector = json('vectors/direct-input.json');
for (const field of ['tbsHex', 'tbsSha256', 'signatureHex', 'publicKeySpkiDerHex',
  'wrongPublicKeySpkiDerHex', 'changedTbsHex', 'prehashedTbsHex'])
  assert.match(vector[field], /^(?:[a-f0-9]{2})+$/, field);

const evidence = json('vectors/operation-evidence.json');
assert(json('sources.json').sources.some(source => source.id === evidence.selectedDraft));
for (const field of [evidence.keyGeneration.credentialIdHex,
  evidence.keyGeneration.keyHandleHex, evidence.keyGeneration.cosePublicKeyHex,
  evidence.signingOperation.tbsHex, evidence.signingOperation.signatureHex])
  assert.match(field, /^(?:[a-f0-9]{2})+$/);
assert.equal(evidence.keyGeneration.attestation.status, 'unavailable');
assert.equal(evidence.signingOperation.associatedWebAuthnResult.status, 'unavailable');
const assertion = json('vectors/assertion-shape.json');
for (const field of ['challengeHex', 'authenticatorDataHex', 'clientDataJSONHex',
  'assertionInputSha256', 'credentialPublicKeySpkiDerHex', 'assertionSignatureHex'])
  assert.match(assertion[field], /^(?:[a-f0-9]{2})+$/, field);

function walk(directory = '') {
  for (const entry of readdirSync(join(root, directory), {withFileTypes: true})) {
    if (entry.name === 'node_modules' || entry.name === '.runtime' || entry.name === '.git') continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walk(path);
    else {
      const value = readFileSync(join(root, path), 'utf8');
      assert(!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(value), path);
      assert(!/github_pat_[A-Za-z0-9_]{40,}|gh[pousr]_[A-Za-z0-9]{30,}/.test(value), path);
    }
  }
}
walk();
console.log('Draft source pins, synthetic vectors and publication content verified');
