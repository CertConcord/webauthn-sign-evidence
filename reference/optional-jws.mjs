import {createHash, createPublicKey, verify} from 'node:crypto';

const strictUtf8 = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});

// A synthetic Ed25519-only application option, not a WebAuthn extension output.
export function prepareSyntheticCompactJws(protectedHeaderBytes, payloadBytes) {
  const header = Buffer.from(protectedHeaderBytes);
  const payload = Buffer.from(payloadBytes);
  const headerText = strictUtf8.decode(header);
  if (!/^\{[\x20\t\r\n]*"alg"[\x20\t\r\n]*:[\x20\t\r\n]*"EdDSA"[\x20\t\r\n]*\}$/.test(headerText))
    throw new TypeError('This synthetic option requires a protected EdDSA header');
  const signingInput = Buffer.from(
    `${header.toString('base64url')}.${payload.toString('base64url')}`, 'ascii');
  return Object.freeze({
    toBeSignedBytes: () => Buffer.from(signingInput),
    complete(signatureBytes, publicKeySpkiDer) {
      const signature = Buffer.from(signatureBytes);
      const publicKey = createPublicKey({
        key: Buffer.from(publicKeySpkiDer), format: 'der', type: 'spki',
      });
      if (publicKey.asymmetricKeyType !== 'ed25519' || signature.length !== 64 ||
          !verify(null, signingInput, publicKey, signature))
        throw new TypeError('Signature does not verify over the exact JWS signing input');
      const completeBytes = Buffer.concat([
        signingInput, Buffer.from('.', 'ascii'),
        Buffer.from(signature.toString('base64url'), 'ascii'),
      ]);
      return Object.freeze({
        serializedBytes: () => Buffer.from(completeBytes),
        sha256Imprint: () => createHash('sha256').update(completeBytes).digest('hex'),
      });
    },
  });
}
