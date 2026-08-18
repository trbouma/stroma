# Acorn Migration to Stroma

## Summary

Migration should be incremental. Stroma is not yet a drop-in dependency, and
Acorn should continue using `monstr` until each boundary is covered by unit,
interoperability, and live tests.

## Current Acorn dependency surface

Acorn currently uses `monstr` from seven source modules for:

- keys and NIP-19 conversion;
- event construction, signing, tag access, and validation;
- NIP-44 storage and transfer encryption;
- custom NIP-59 gift wrapping;
- relay clients, pools, subscriptions, and queries;
- small formatting utilities.

The unused NIP-04 ecash-direct-message paths were removed after confirming that
Safebox Web, Clear, Grove, Mainstay, and Stroma had no callers. Historical
`last_dm` relay records remain hidden as legacy system records, but new Acorns
no longer create or replicate that cursor. Stroma therefore does not need to
implement NIP-04 for the Acorn migration.

## Migration sequence

1. Add Stroma as a development dependency without changing runtime imports.
2. Run Stroma's official NIP-44 vectors and Acorn interoperability fixtures.
3. Replace Acorn's custom `ExtendedNIP44Encrypt` with Stroma NIP-44.
4. Replace the custom gift-wrap implementation with Stroma NIP-59 while
   preserving Acorn's zero-jitter, rumour-kind, and expiration policies.
5. Migrate event, tag, signer, key, and NIP-19 imports.
6. Introduce an Acorn relay adapter and migrate publish/query paths in small
   groups.
7. Run all Acorn unit and live relay-suitability tests.
8. Remove `monstr` only when no compatibility imports remain.

## Required migration gates

- Official NIP-44 vectors pass, including the 65,535/65,536 boundary.
- Stroma can decrypt existing Acorn NIP-44 events and vice versa below the
  legacy payload boundary.
- Existing gift-wrapped funds transfers can be received.
- New Stroma gift wraps can be received by the deployed Acorn implementation.
- Event IDs and signatures match independent implementations.
- Relay clients close without pending tasks or event-loop warnings.
- Publish acknowledgement and read-after-write behavior remain explicit.
- The complete Acorn non-live and live suites pass.

## Relay migration caution

Relay behavior is the highest-risk migration surface. Acorn depends on
timeouts, EOSE completion, publication acknowledgements, deduplication, and
clean async shutdown. Stroma initially provides operation-scoped
`RelayClient` and `RelayPool` APIs; a compatibility adapter should be designed
from observed Acorn behavior rather than copying the entire historical client.
