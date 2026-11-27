# WebAuthn sign extension evidence research

This repository studies the evidence needed when an application uses the **proposed** WebAuthn `sign` extension for document signatures. It tracks the [W3C sign-extension branch](https://github.com/w3c/webauthn/tree/sign-extension), [PR #2078](https://github.com/w3c/webauthn/pull/2078), and [YubicoLabs' published v6 draft](https://github.com/YubicoLabs/webauthn-sign-extension/tree/sign-extension-v6) as separate, pinned sources. PR #2078 was open and unmerged at the supplemental source review; this repository does not claim an adopted extension or working browser/authenticator support.

[Draft](draft.md) defines the evidence questions and boundaries. [Sources](sources.json) records exact source commits and bytes. [Cases](cases.json) and [synthetic vectors](vectors/direct-input.json) test direct signature input bytes, an assertion-shaped boundary and evidence-policy separation. A [conditional compact JWS vector](vectors/optional-jws.json) tests construction order and the exact bytes of one possible RFC 3161 imprint target. [Synthetic response fixtures](vectors/optional-jws-response.json) exercise that byte target with a locally issued test certificate and OpenSSL response verification. They are not an extension-defined or selected timestamp profile. These examples do not implement WebAuthn, verify attestation, produce a PAdES/CAdES/JAdES container, or establish trusted TSA time.

The synthetic JWS accepts genuine byte arrays and subviews at its construction boundary. It retains and returns separate, exact-sized byte stores so a caller cannot change the frozen signing input, completed JWS or imprint through a returned buffer.

The synthetic response tests also isolate the TSA certificate identifier from the CMS signature by substituting a same-key test certificate. A fixed test verification epoch keeps the certificate replay reproducible; it does not confer current trust.

A [synthetic outer byte record](vectors/outer-evidence.json) retains the frozen JWS, original request DER, response DER and a later opaque log artifact in separate fields. Restore rejects duplicate decoded JSON field names, and retained and returned bytes use independent backing storage. Its tests distinguish storage and first-imprint coverage from response validation and log-proof validation. This record does not select RFC 5544, an archive profile, or a transparency-log protocol.

A [second synthetic timestamp vector](vectors/later-timestamp.json) freezes the exact serialized outer record after its first response and opaque log bytes have been retained. A separate request hashes that snapshot; its request and response remain outside the snapshot. Byte changes, JSON reserialization and restoration test the two imprint boundaries independently under a fixed test-root replay epoch. This is an application candidate, not a trusted timestamp renewal or log proof.

An [offline synthetic log vector](vectors/log-proof.json) explores a separate application entry for the complete JWS digest under the released C2SP tiled-log and signed-checkpoint formats. A [test-only policy fixture](vectors/log-test-policy.json) supplies the log key, origin and previously accepted checkpoint separately from the proof. The caller must validate that policy origin under the selected C2SP checkpoint syntax; the sample only compares it with the signed origin. The tests check a signed checkpoint, entry bundle, partial tile, inclusion path and append-only consistency, then retain those proof bytes in a new outer snapshot and issue a new test-root second timestamp. No deployed log, witness, real trust anchor or timestamp authority is established.

The application log-entry label, each returned 39-byte entry and every restored proof byte field have separate, exact-sized backing stores. A caller holding a returned buffer cannot change another field, a later entry or the label used for a proof check through Node's shared Buffer pool.

An [additive v6/W3C source-model vector](vectors/source-v6-model.json) tests parent/child algorithm support-list positions, the distinct errors for an unsupported pair and an unavailable algorithm, candidate order, and signing-child self-attestation fallback. It compares only the historical Framework PSCP format gate and does not simulate an authenticator, verify attestation or update Framework's selected source.

A [source-exact v6 ML-DSA example](vectors/source-v6-ml-dsa-example.json) exercises the published sparse matrix: eight excluded parent/child pairs out of 36 possible, with error and later-candidate checks. It describes a draft example, not a device capability claim or a selected PQC document profile.

A [synthetic v6 CBOR boundary vector](vectors/source-v6-cbor-boundary.json) connects the draft's inner `kh`/`tbs` request map and `sig` output map to the existing Ed25519 compact JWS example. It verifies the exact `tbs` content bytes, excludes the CBOR byte-string header and full map from the signature input, then hashes the completed JWS. The narrow decoder does not parse WebAuthn, validate a signing key handle or attest an authenticator.

Run with Node.js 24.15 or later and OpenSSL 3.x on `PATH`:

    npm run check
    npm test

Original text is under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). The linked upstream material retains its own rights and status. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).
