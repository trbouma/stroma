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

## Blossom destinations and data

BlossomPool accepts only public HTTPS origins by default. Literal addresses and
the DNS addresses passed to the connector are checked; redirects, environment
proxies, cookies, and automatic content decompression are disabled. Application
egress controls and server allowlists are still recommended. Private-network and
plain-HTTP opt-ins are for operator-controlled environments, not user input.

Uploads use short-lived authorization scoped to one digest and server domain.
Never log authorization headers or signing keys. Retrieved bytes must match the
requested SHA-256, but their content and declared media type remain untrusted.
Read-back confirmation establishes availability at that moment, not durable
retention, provenance, safety to render, or legal effect.

## Current status

Stroma is pre-release and has not received an independent security audit. It
must not replace Acorn's current dependency until compatibility, official
vectors, malformed-input behavior, and live relay operation have been tested.

## Reporting

Do not publish a suspected vulnerability before coordinating a fix. Contact
the project maintainer privately with a minimal reproduction and affected
version.
