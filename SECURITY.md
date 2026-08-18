# Security

Stroma processes private keys, signed events, encrypted payloads, and
untrusted relay input. Treat all protocol parsing as a security boundary.

## Design commitments

- Do not invent cryptographic primitives.
- Use established secp256k1 and ChaCha20 implementations.
- Validate event identifiers and signatures before trusting relay events.
- Authenticate NIP-44 ciphertext before decoding plaintext.
- Apply configurable size limits before expensive decoding or allocation.
- Use operating-system randomness for keys, nonces, and signatures.
- Keep relay input, timeouts, and connection lifecycles bounded.
- Test against official protocol vectors and malformed inputs.

## Current status

Stroma is pre-release and has not received an independent security audit. It
must not replace Acorn's current dependency until compatibility, official
vectors, malformed-input behavior, and live relay operation have been tested.

## Reporting

Do not publish a suspected vulnerability before coordinating a fix. Contact
the project maintainer privately with a minimal reproduction and affected
version.
