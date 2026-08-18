# Security

## Summary

Stroma operates at a sensitive boundary: it processes private keys, signed
events, encrypted payloads, and untrusted relay input. Security properties are
made explicit and tested rather than inferred from successful transport.

## Current safeguards

- operating-system randomness for keys, nonces, and signatures;
- canonical event hashing and independent BIP-340 verification;
- authenticated NIP-44 decryption before plaintext decoding;
- constant-time MAC comparison;
- configurable plaintext and payload-size ceilings;
- recipient and signature checks during gift-wrap unwrapping;
- bounded relay timeouts and operation-scoped connections;
- official protocol vectors and malformed-input tests.

## Trust boundary

Stroma verifies protocol mechanics. It cannot determine whether an event's
author should be trusted, whether a relay is complete, or whether application
content is true. Those judgments belong to Acorn and the applications using
it.

## Current limitations

Stroma is unaudited pre-release software. Its current relay interface is
deliberately small and has not yet completed Acorn's live relay-suitability
suite. NIP-44 protects message confidentiality and integrity under its stated
cryptographic assumptions; Stroma does not claim to make secp256k1 key exchange
post-quantum resistant.

[Read the full security policy](https://github.com/trbouma/stroma/blob/main/SECURITY.md){ .md-button .md-button--primary }
