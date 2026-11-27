import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const source = JSON.parse(readFileSync(new URL('../vectors/optional-jws.json', import.meta.url)));
const vector = JSON.parse(readFileSync(new URL('../vectors/optional-jws-response.json', import.meta.url)));
const sha256 = value => createHash('sha256').update(value).digest('hex');
const fromHex = value => Buffer.from(value, 'hex');
const fromBase64 = value => Buffer.from(value, 'base64');

function runOpenSsl(args) {
  const result = spawnSync('openssl', args, {encoding: 'utf8', timeout: 15_000});
  if (result.error) throw result.error;
  return result;
}

function verifyResponse({response, request, artifact, root}) {
  const directory = mkdtempSync(join(tmpdir(), 'webauthn-ts-test-'));
  try {
    const responsePath = join(directory, 'response.der');
    const rootPath = join(directory, 'test-root.pem');
    writeFileSync(responsePath, response);
    writeFileSync(rootPath, root);
    const args = ['ts', '-verify', '-in', responsePath, '-CAfile', rootPath];
    if (request) {
      const path = join(directory, 'request.der');
      writeFileSync(path, request);
      args.push('-queryfile', path);
    } else {
      const path = join(directory, 'artifact.jws');
      writeFileSync(path, artifact);
      args.push('-data', path);
    }
    return runOpenSsl(args);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
}

const response = fromBase64(vector.positiveResponseDerBase64);
const request = fromHex(vector.originalRequestDerHex);
const artifact = Buffer.from(source.compactAscii, 'ascii');
const testRoot = Buffer.from(vector.testRootPem, 'ascii');

test('public response fixtures retain the probed bytes and test-only scope', () => {
  assert.equal(artifact.length, 136);
  assert.equal(sha256(artifact), source.compactSha256);
  assert.equal(vector.sourceCompactSha256, source.compactSha256);
  assert.equal(request.toString('hex'), source.timestampRequestDerHex);
  const fixtures = {
    'timestamp-optional-request.tsq': request,
    'tsa-test-positive.tsr': response,
    'tsa-test-root.pem': testRoot,
    'tsa-test-leaf.pem': Buffer.from(vector.testLeafPem, 'ascii'),
    'tsa-test-other-root.pem': Buffer.from(vector.otherTestRootPem, 'ascii'),
    'tsa-test-nonce.tsq': fromHex(vector.nonceRequestDerHex),
    'tsa-test-nonce-mismatch.tsq': fromHex(vector.nonceMismatchRequestDerHex),
    'tsa-test-nonce.tsr': fromBase64(vector.nonceResponseDerBase64),
    'tsa-test-policy.tsq': fromHex(vector.policyRequestDerHex),
    'tsa-test-policy-mismatch.tsq': fromHex(vector.policyMismatchRequestDerHex),
    'tsa-test-policy.tsr': fromBase64(vector.policyResponseDerBase64),
    'tsa-test-imprint-bitflip.tsr': fromBase64(vector.imprintBitflipResponseDerBase64),
    'tsa-test-status-granted-without-token.tsr': fromHex(vector.grantedWithoutTokenDerHex),
    'tsa-test-status-rejection-with-token.tsr': fromBase64(vector.rejectionWithTokenDerBase64),
  };
  assert.deepEqual(Object.keys(fixtures).sort(), Object.keys(vector.fixtureSha256).sort());
  for (const [name, bytes] of Object.entries(fixtures)) {
    assert.equal(sha256(bytes), vector.fixtureSha256[name], name);
  }
  assert.equal(vector.privateKeyPublished, false);
  assert.equal(vector.trustedTimeEstablished, false);
  assert.equal(vector.nonceFreeRequestTimelinessEstablished, false);
  assert.equal(vector.testRootPem.includes('PRIVATE KEY'), false);
  assert.equal(vector.testLeafPem.includes('PRIVATE KEY'), false);
});

test('the synthetic certificate explicitly carries a critical time-stamping EKU', () => {
  // Pass the public certificate through stdin so the test never needs the test key.
  const certificate = spawnSync('openssl', ['x509', '-noout', '-text'], {
    input: vector.testLeafPem, encoding: 'utf8', timeout: 15_000,
  });
  assert.equal(certificate.error, undefined);
  assert.equal(certificate.status, 0, certificate.stderr);
  assert.match(certificate.stdout, /X509v3 Extended Key Usage: critical\s+Time Stamping/);
});

test('complete frozen JWS bytes bind to a signed response under the synthetic root', () => {
  const byRequest = verifyResponse({response, request, root: testRoot});
  const byArtifact = verifyResponse({response, artifact, root: testRoot});
  assert.equal(byRequest.status, 0, byRequest.stderr);
  assert.match(byRequest.stdout, /Verification: OK/);
  assert.equal(byArtifact.status, 0, byArtifact.stderr);
  assert.match(byArtifact.stdout, /Verification: OK/);
});

test('changed signature octet and reserialized, correctly re-signed JWS fail the original imprint', () => {
  const changed = Buffer.from(artifact);
  const signatureStart = changed.lastIndexOf(0x2e) + 1;
  assert.equal(changed[signatureStart], 0x42);
  changed[signatureStart] = 0x41;
  assert.equal(sha256(changed), 'ac2689bf3aed9218b09c14bc201b6167633992c4e92a89041fbab85f627a0006');
  const altered = verifyResponse({response, artifact: changed, root: testRoot});
  assert.notEqual(altered.status, 0);
  assert.match(altered.stdout, /Verification: FAILED/);
  const reserialized = Buffer.from(source.reserializedCompactAscii, 'ascii');
  assert.equal(sha256(reserialized), source.reserializedCompactSha256);
  const rebuilt = verifyResponse({response, artifact: reserialized, root: testRoot});
  assert.notEqual(rebuilt.status, 0);
  assert.match(rebuilt.stdout, /Verification: FAILED/);
  changed[signatureStart] = 0x42;
  assert.deepEqual(changed, artifact);
  assert.equal(verifyResponse({response, artifact: changed, root: testRoot}).status, 0);
});

test('response imprint mutation, invalid status/token pairing and wrong test root fail', () => {
  for (const [name, invalidResponse] of [
    ['imprint bitflip', fromBase64(vector.imprintBitflipResponseDerBase64)],
    ['granted without token', fromHex(vector.grantedWithoutTokenDerHex)],
    ['rejection with token', fromBase64(vector.rejectionWithTokenDerBase64)],
  ]) {
    const result = verifyResponse({response: invalidResponse, request, root: testRoot});
    assert.notEqual(result.status, 0, name);
    assert.match(result.stdout, /Verification: FAILED/, name);
  }
  const wrongRoot = verifyResponse({response, request,
    root: Buffer.from(vector.otherTestRootPem, 'ascii')});
  assert.notEqual(wrongRoot.status, 0);
  assert.match(wrongRoot.stdout, /Verification: FAILED/);
});

test('nonce and requested policy changes fail against their separately signed responses', () => {
  for (const [name, responseBytes, matchingRequest, changedRequest] of [
    ['nonce', fromBase64(vector.nonceResponseDerBase64),
      fromHex(vector.nonceRequestDerHex), fromHex(vector.nonceMismatchRequestDerHex)],
    ['policy', fromBase64(vector.policyResponseDerBase64),
      fromHex(vector.policyRequestDerHex), fromHex(vector.policyMismatchRequestDerHex)],
  ]) {
    const positive = verifyResponse({response: responseBytes,
      request: matchingRequest, root: testRoot});
    assert.equal(positive.status, 0, `${name}: ${positive.stderr}`);
    assert.match(positive.stdout, /Verification: OK/);
    const negative = verifyResponse({response: responseBytes,
      request: changedRequest, root: testRoot});
    assert.notEqual(negative.status, 0, name);
    assert.match(negative.stdout, /Verification: FAILED/);
  }
});
