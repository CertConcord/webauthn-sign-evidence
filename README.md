# WebAuthn sign extension evidence research

This repository studies the evidence needed when an application uses the **proposed** WebAuthn `sign` extension for document signatures. It tracks the [W3C sign-extension branch](https://github.com/w3c/webauthn/tree/sign-extension), [draft PR #2078](https://github.com/w3c/webauthn/pull/2078), and [YubicoLabs' evolving draft](https://github.com/YubicoLabs/webauthn-sign-extension) as separate, pinned sources. The PR is not merged; this repository does not claim an adopted extension or working browser/authenticator support.

[Draft](draft.md) defines the evidence questions and boundaries. [Sources](sources.json) records exact source commits and bytes. [Cases](cases.json) and [synthetic vectors](vectors/direct-input.json) test direct signature input bytes, an assertion-shaped boundary and evidence-policy separation. A [conditional compact JWS vector](vectors/optional-jws.json) tests construction order and the exact bytes of one possible RFC 3161 imprint target. [Synthetic response fixtures](vectors/optional-jws-response.json) exercise that byte target with a locally issued test certificate and OpenSSL response verification. They are not an extension-defined or selected timestamp profile. These examples do not implement WebAuthn, verify attestation, produce a PAdES/CAdES/JAdES container, or establish trusted TSA time.

The synthetic response tests also isolate the TSA certificate identifier from the CMS signature by substituting a same-key test certificate. A fixed test verification epoch keeps the certificate replay reproducible; it does not confer current trust.

A [synthetic outer byte record](vectors/outer-evidence.json) retains the frozen JWS, original request DER, response DER and a later opaque log artifact in separate fields. Restore rejects duplicate decoded JSON field names, and retained and returned bytes use independent backing storage. Its tests distinguish storage and first-imprint coverage from response validation and log-proof validation. This record does not select RFC 5544, an archive profile, or a transparency-log protocol.

A [second synthetic timestamp vector](vectors/later-timestamp.json) freezes the exact serialized outer record after its first response and opaque log bytes have been retained. A separate request hashes that snapshot; its request and response remain outside the snapshot. Byte changes, JSON reserialization and restoration test the two imprint boundaries independently under a fixed test-root replay epoch. This is an application candidate, not a trusted timestamp renewal or log proof.

An [offline synthetic log vector](vectors/log-proof.json) explores a separate application entry for the complete JWS digest under the released C2SP tiled-log and signed-checkpoint formats. A [test-only policy fixture](vectors/log-test-policy.json) supplies the log key, origin and previously accepted checkpoint separately from the proof. The tests check a signed checkpoint, entry bundle, partial tile, inclusion path and append-only consistency, then retain those proof bytes in a new outer snapshot and issue a new test-root second timestamp. No deployed log, witness, real trust anchor or timestamp authority is established.

Run with Node.js 24.15 or later and OpenSSL 3.x on `PATH`:

    npm run check
    npm test

Original text is under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). The linked upstream material retains its own rights and status. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).
