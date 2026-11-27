# WebAuthn sign extension evidence research

This repository studies the evidence needed when an application uses the **proposed** WebAuthn `sign` extension for document signatures. It tracks the [W3C sign-extension branch](https://github.com/w3c/webauthn/tree/sign-extension), [draft PR #2078](https://github.com/w3c/webauthn/pull/2078), and [YubicoLabs' evolving draft](https://github.com/YubicoLabs/webauthn-sign-extension) as separate, pinned sources. The PR is not merged; this repository does not claim an adopted extension or working browser/authenticator support.

[Draft](draft.md) defines the evidence questions and boundaries. [Sources](sources.json) records exact source commits and bytes. [Cases](cases.json) and [synthetic vectors](vectors/direct-input.json) test direct signature input bytes, an assertion-shaped boundary and evidence-policy separation. A [conditional compact JWS vector](vectors/optional-jws.json) tests construction order and the exact bytes of one possible RFC 3161 imprint target. [Synthetic response fixtures](vectors/optional-jws-response.json) exercise that byte target with a locally issued test certificate and OpenSSL response verification. They are not an extension-defined or selected timestamp profile. These examples do not implement WebAuthn, verify attestation, produce a PAdES/CAdES/JAdES container, or establish trusted TSA time.

The synthetic response tests also isolate the TSA certificate identifier from the CMS signature by substituting a same-key test certificate. A fixed test verification epoch keeps the certificate replay reproducible; it does not confer current trust.

Run with Node.js 24.15 or later and OpenSSL 3.x on `PATH`:

    npm run check
    npm test

Original text is under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). The linked upstream material retains its own rights and status. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).
