import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {prepareSyntheticCompactJws} from './optional-jws.mjs';

const source = JSON.parse(readFileSync(new URL('../vectors/optional-jws.json', import.meta.url)));
const vector = JSON.parse(readFileSync(new URL('../vectors/optional-jws-response.json', import.meta.url)));
const validMismatch = JSON.parse(readFileSync(new URL('../vectors/optional-jws-valid-imprint-mismatch.json', import.meta.url)));
const sha256 = value => createHash('sha256').update(value).digest('hex');
const fromHex = value => Buffer.from(value, 'hex');
const fromBase64 = value => Buffer.from(value, 'base64');
const replayEpoch = String(vector.verificationEpochSeconds);

function runOpenSsl(args) {
  const result = spawnSync('openssl', args, {encoding: 'utf8', timeout: 15_000});
  if (result.error) throw result.error;
  return result;
}

function verifyResponse({response, request, artifact, root, epoch = replayEpoch}) {
  const directory = mkdtempSync(join(tmpdir(), 'webauthn-ts-test-'));
  try {
    const responsePath = join(directory, 'response.der');
    const rootPath = join(directory, 'test-root.pem');
    writeFileSync(responsePath, response);
    writeFileSync(rootPath, root);
    const args = ['ts', '-verify', '-in', responsePath, '-CAfile', rootPath,
      '-attime', epoch];
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
    'tsa-test-leaf-same-key-altered.pem': Buffer.from(vector.sameKeyAlternateTestLeafPem, 'ascii'),
    'tsa-test-esscertid-mismatch.tsr': fromBase64(vector.essCertIdMismatchResponseDerBase64),
  };
  assert.deepEqual(Object.keys(fixtures).sort(), Object.keys(vector.fixtureSha256).sort());
  for (const [name, bytes] of Object.entries(fixtures)) {
    assert.equal(sha256(bytes), vector.fixtureSha256[name], name);
  }
  assert.equal(vector.privateKeyPublished, false);
  assert.equal(vector.verificationEpochSeconds, 1795744800);
  assert.equal(vector.trustedTimeEstablished, false);
  assert.equal(vector.nonceFreeRequestTimelinessEstablished, false);
  assert.equal(vector.testRootPem.includes('PRIVATE KEY'), false);
  assert.equal(vector.testLeafPem.includes('PRIVATE KEY'), false);
  assert.equal(vector.sameKeyAlternateTestLeafPem.includes('PRIVATE KEY'), false);
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

test('same-key certificate substitution preserves CMS signature but fails ESSCertID', () => {
  const certificate = pem => {
    const der = spawnSync('openssl', ['x509', '-outform', 'DER'], {
      input: pem, timeout: 15_000,
    });
    assert.equal(der.status, 0, der.stderr?.toString());
    return der.stdout;
  };
  const certificateText = (pem, ...args) => {
    const result = spawnSync('openssl', ['x509', '-noout', ...args], {
      input: pem, encoding: 'utf8', timeout: 15_000,
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  const originalCert = certificate(vector.testLeafPem);
  const alternateCert = certificate(vector.sameKeyAlternateTestLeafPem);
  assert.equal(originalCert.length, alternateCert.length);
  assert.notDeepEqual(originalCert, alternateCert);
  assert.equal(certificateText(vector.testLeafPem, '-pubkey'),
    certificateText(vector.sameKeyAlternateTestLeafPem, '-pubkey'));
  assert.equal(certificateText(vector.testLeafPem, '-issuer', '-serial'),
    certificateText(vector.sameKeyAlternateTestLeafPem, '-issuer', '-serial'));
  assert.match(certificateText(vector.sameKeyAlternateTestLeafPem, '-text'),
    /X509v3 Extended Key Usage: critical\s+Time Stamping/);
  assert.equal(response.indexOf(originalCert), response.lastIndexOf(originalCert));
  const alteredResponse = fromBase64(vector.essCertIdMismatchResponseDerBase64);
  const expectedResponse = Buffer.from(response);
  alternateCert.copy(expectedResponse, response.indexOf(originalCert));
  assert.deepEqual(alteredResponse, expectedResponse);

  const directory = mkdtempSync(join(tmpdir(), 'webauthn-ess-test-'));
  try {
    const rootPath = join(directory, 'root.pem');
    const alternatePath = join(directory, 'alternate.pem');
    const responsePath = join(directory, 'response.der');
    const tokenPath = join(directory, 'token.der');
    writeFileSync(rootPath, testRoot);
    writeFileSync(alternatePath, vector.sameKeyAlternateTestLeafPem);
    writeFileSync(responsePath, alteredResponse);
    const chain = runOpenSsl(['verify', '-purpose', 'timestampsign', '-CAfile',
      rootPath, '-attime', replayEpoch, alternatePath]);
    assert.equal(chain.status, 0, chain.stderr);
    const extraction = runOpenSsl(['ts', '-reply', '-in', responsePath,
      '-token_out', '-out', tokenPath]);
    assert.equal(extraction.status, 0, extraction.stderr);
    const cms = runOpenSsl(['cms', '-verify', '-inform', 'DER', '-in', tokenPath,
      '-CAfile', rootPath, '-purpose', 'any', '-attime', replayEpoch,
      '-out', join(directory, 'content.der')]);
    assert.equal(cms.status, 0, cms.stderr);
    const timestamp = verifyResponse({response: alteredResponse, request, root: testRoot});
    assert.notEqual(timestamp.status, 0);
    assert.match(timestamp.stdout, /Verification: FAILED/);
    assert.match(timestamp.stderr, /ess cert id not found/i);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
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

test('a validly signed token for another complete JWS cannot claim the original imprint', () => {
  const alternate = Buffer.from(source.reserializedCompactAscii, 'ascii');
  const alternateRequest = fromHex(validMismatch.alternateRequestDerHex);
  const alternateResponse = fromBase64(validMismatch.alternateResponseDerBase64);
  const epoch = String(validMismatch.verificationEpochSeconds);
  assert.equal(sha256(alternate), validMismatch.alternateCompleteJwsSha256);
  assert.equal(sha256(artifact), validMismatch.originalCompleteJwsSha256);
  assert.notEqual(validMismatch.alternateCompleteJwsSha256,
    validMismatch.originalCompleteJwsSha256);
  assert.equal(sha256(alternateRequest), validMismatch.requestSha256);
  assert.equal(sha256(alternateResponse), validMismatch.responseSha256);
  const sameFieldsAsOriginal = Buffer.from(alternateRequest);
  const imprintOffset = sameFieldsAsOriginal.indexOf(
    fromHex(validMismatch.alternateCompleteJwsSha256));
  assert.notEqual(imprintOffset, -1);
  fromHex(validMismatch.originalCompleteJwsSha256)
    .copy(sameFieldsAsOriginal, imprintOffset);
  assert.deepEqual(sameFieldsAsOriginal, request);
  assert(Date.parse(validMismatch.tokenGenTime) <
    validMismatch.verificationEpochSeconds * 1000);
  assert.equal(validMismatch.privateKeyPublished, false);
  assert.equal(validMismatch.trustedTimeEstablished, false);
  assert.equal(validMismatch.responseTimelinessEstablished, false);
  const completed = prepareSyntheticCompactJws(
    fromHex(source.reserializedHeaderUtf8Hex), fromHex(source.payloadHex))
    .complete(fromHex(source.reserializedSignatureHex),
      fromHex(source.publicKeySpkiDerHex));
  assert.deepEqual(completed.serializedBytes(), alternate);

  for (const input of [{request: alternateRequest}, {artifact: alternate}]) {
    const positive = verifyResponse({response: alternateResponse, ...input,
      root: testRoot, epoch});
    assert.equal(positive.status, 0, positive.stderr);
    assert.match(positive.stdout, /Verification: OK/);
  }
  for (const input of [{request}, {artifact}]) {
    const rejected = verifyResponse({response: alternateResponse, ...input,
      root: testRoot, epoch});
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stdout, /Verification: FAILED/);
    assert.match(rejected.stderr, /message imprint mismatch/i);
  }

  const directory = mkdtempSync(join(tmpdir(), 'webauthn-ts-imprint-'));
  try {
    const responsePath = join(directory, 'response.der');
    const tokenPath = join(directory, 'token.der');
    const contentPath = join(directory, 'content.der');
    const rootPath = join(directory, 'root.pem');
    writeFileSync(responsePath, alternateResponse);
    writeFileSync(rootPath, testRoot);
    const described = runOpenSsl(['ts', '-reply', '-in', responsePath, '-text']);
    assert.equal(described.status, 0, described.stderr);
    const renderedTime = described.stdout.match(/Time stamp: (.+ GMT)/);
    assert(renderedTime);
    assert.equal(Date.parse(renderedTime[1]), Date.parse(validMismatch.tokenGenTime));
    const extracted = runOpenSsl(['ts', '-reply', '-in', responsePath,
      '-token_out', '-out', tokenPath]);
    assert.equal(extracted.status, 0, extracted.stderr);
    const cms = runOpenSsl(['cms', '-verify', '-binary', '-inform', 'DER', '-in', tokenPath,
      '-CAfile', rootPath, '-purpose', 'any', '-attime', epoch,
      '-out', contentPath]);
    assert.equal(cms.status, 0, cms.stderr);
    assert.match(cms.stderr, /CMS Verification successful/);
    const signedContent = readFileSync(contentPath);
    assert.equal(signedContent.length, 139);
    const readDer = (bytes, offset) => {
      assert(offset + 2 <= bytes.length);
      const tag = bytes[offset];
      const marker = bytes[offset + 1];
      let length = marker;
      let headerLength = 2;
      if (marker & 0x80) {
        const octets = marker & 0x7f;
        assert(octets > 0 && octets <= 4 && offset + 2 + octets <= bytes.length);
        length = 0;
        for (let index = 0; index < octets; index += 1) {
          length = (length * 256) + bytes[offset + 2 + index];
        }
        assert(length >= 128);
        headerLength += octets;
      }
      const valueStart = offset + headerLength;
      const end = valueStart + length;
      assert(end <= bytes.length);
      return {tag, valueStart, end};
    };
    const tstInfo = readDer(signedContent, 0);
    assert.equal(tstInfo.tag, 0x30);
    assert.equal(tstInfo.end, signedContent.length);
    const version = readDer(signedContent, tstInfo.valueStart);
    assert.equal(version.tag, 0x02);
    const policy = readDer(signedContent, version.end);
    assert.equal(policy.tag, 0x06);
    const imprint = readDer(signedContent, policy.end);
    assert.equal(imprint.tag, 0x30);
    const algorithm = readDer(signedContent, imprint.valueStart);
    assert.equal(algorithm.tag, 0x30);
    const oid = readDer(signedContent, algorithm.valueStart);
    assert.equal(oid.tag, 0x06);
    assert.deepEqual(signedContent.subarray(oid.valueStart, oid.end),
      fromHex('608648016503040201'));
    const nullParameter = readDer(signedContent, oid.end);
    assert.equal(nullParameter.tag, 0x05);
    assert.equal(nullParameter.valueStart, nullParameter.end);
    assert.equal(nullParameter.end, algorithm.end);
    const digest = readDer(signedContent, algorithm.end);
    assert.equal(digest.tag, 0x04);
    assert.equal(digest.end, imprint.end);
    assert.deepEqual(signedContent.subarray(digest.valueStart, digest.end),
      fromHex(validMismatch.alternateCompleteJwsSha256));
    assert.notDeepEqual(signedContent.subarray(digest.valueStart, digest.end),
      fromHex(validMismatch.originalCompleteJwsSha256));
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
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
