import {createHash, createPublicKey, verify} from 'node:crypto';
import {types} from 'node:util';

const strictUtf8 = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});

function ownedBytes(value, name) {
  if (!types.isUint8Array(value))
    throw new TypeError(`${name} must be native bytes`);
  return Buffer.from(new Uint8Array(value).buffer);
}

// A synthetic Ed25519-only application option, not a WebAuthn extension output.
export function prepareSyntheticCompactJws(protectedHeaderBytes, payloadBytes) {
  const header = ownedBytes(protectedHeaderBytes, 'protected header');
  const payload = ownedBytes(payloadBytes, 'payload');
  const headerText = strictUtf8.decode(header);
  if (!/^\{[\x20\t\r\n]*"alg"[\x20\t\r\n]*:[\x20\t\r\n]*"EdDSA"[\x20\t\r\n]*\}$/.test(headerText))
    throw new TypeError('This synthetic option requires a protected EdDSA header');
  const signingInput = ownedBytes(Buffer.from(
    `${header.toString('base64url')}.${payload.toString('base64url')}`, 'ascii'),
  'JWS signing input');
  return Object.freeze({
    toBeSignedBytes: () => ownedBytes(signingInput, 'JWS signing input'),
    complete(signatureBytes, publicKeySpkiDer) {
      const signature = ownedBytes(signatureBytes, 'signature');
      const publicKey = createPublicKey({
        key: ownedBytes(publicKeySpkiDer, 'public key'), format: 'der', type: 'spki',
      });
      if (publicKey.asymmetricKeyType !== 'ed25519' || signature.length !== 64 ||
          !verify(null, signingInput, publicKey, signature))
        throw new TypeError('Signature does not verify over the exact JWS signing input');
      const completeBytes = ownedBytes(Buffer.concat([
        signingInput, Buffer.from('.', 'ascii'),
        Buffer.from(signature.toString('base64url'), 'ascii'),
      ]), 'complete compact JWS');
      return Object.freeze({
        serializedBytes: () => ownedBytes(completeBytes, 'complete compact JWS'),
        sha256Imprint: () => createHash('sha256').update(completeBytes).digest('hex'),
      });
    },
  });
}
