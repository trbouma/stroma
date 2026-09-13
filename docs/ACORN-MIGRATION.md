# Acorn Migration to Stroma

## Summary

Acorn's runtime imports have migrated from `monstr` to Stroma. The replacement
keeps Stroma deliberately narrow: relay reads and writes are bounded,
operation-scoped calls rather than an application-wide background client.

The migration is complete at the source and non-live-test boundary. Deployment
remains gated on publishing and pinning the tested Stroma revision, regenerating
Acorn's lock file, and passing Acorn's configured live relay tests.

## Current Acorn dependency surface

Acorn requires Stroma for:

- keys and NIP-19 conversion;
- event construction, signing, tag access, and validation;
- NIP-44 storage and transfer encryption;
- NIP-59 gift wrapping with Acorn's zero-jitter and expiration policy;
- bounded relay publication, acknowledgement, connectivity probes, and EOSE
  queries;
- small formatting utilities.

The unused NIP-04 ecash-direct-message paths were removed after confirming that
Safebox Web, Clear, Grove, Mainstay, and Stroma had no callers. Historical
`last_dm` relay records remain hidden as legacy system records, but new Acorns
no longer create or replicate that cursor. Stroma therefore does not need to
implement NIP-04 for the Acorn migration.

## Implemented migration

1. Event, tag, signer, key, NIP-19, NIP-44, and NIP-59 imports now resolve to
   Stroma.
2. Acorn's relay-shaped compatibility surface is provided by Stroma and backed
   by `RelayClient` and `RelayPool`.
3. Context-managed publication waits for acknowledgement and propagates
   failures before returning.
4. Queries and relay connectivity probes have explicit time budgets.
5. The Monstr dependency and its leaked-task cleanup fixtures have been removed
   from Acorn source and tests.
6. Long-lived subscription behavior is not part of the initial Acorn boundary;
   current wallet, record, and incoming-funds paths use finite relay queries.

## Required migration gates

- Official NIP-44 vectors pass, including the 65,535/65,536 boundary.
- Stroma can decrypt existing Acorn NIP-44 events and vice versa below the
  legacy payload boundary.
- Existing gift-wrapped funds transfers can be received.
- New Stroma gift wraps can be received by the deployed Acorn implementation.
- Event IDs and signatures match independent implementations.
- Relay clients close without pending tasks or event-loop warnings.
- Publish acknowledgement and read-after-write behavior remain explicit.
- The complete Acorn non-live suite passes.
- Configured live relay-suitability and interoperability suites pass before a
  production dependency pin is advanced.

## Relay migration caution

Relay behavior remains the highest-risk migration surface. Acorn depends on
timeouts, EOSE completion, publication acknowledgements, deduplication, and
clean async shutdown. Stroma's compatibility adapter maps only the observed
finite Acorn operations onto operation-scoped `RelayClient` and `RelayPool`
calls. It intentionally does not recreate a general social-client framework.

This boundary matters operationally: constructing an Acorn must not start
unbounded relay tasks, and leaving an operation's context must not leave
WebSocket or publish tasks behind.

## Deployment order

1. Commit and publish the tested Stroma revision.
2. Pin Acorn to that Stroma tag or commit.
3. Regenerate `poetry.lock` in Acorn.
4. Run Stroma tests, the complete Acorn non-live suite, and configured live
   relay tests.
5. Update and test each consuming application's Acorn pin.
