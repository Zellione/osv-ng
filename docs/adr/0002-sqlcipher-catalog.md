# ADR 0002: SQLCipher catalog

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Encrypted catalog; Phase 1 prototype 4; Phase 5
- Supersedes: none

## Context

Names, metadata, gallery relationships, tags, favorites, search data, wrapped
object keys, and operation journals need relational integrity without plaintext
pages or temporary artifacts. Implementing a bespoke encrypted database would
create unacceptable format, query, and recovery risk.

## Decision

Use SQLCipher behind repository interfaces. Phase 1 validated raw derived-key
opening, authenticated pages, WAL recovery/checkpointing, memory-only temporary
storage, and absence of plaintext canaries in all disk artifacts. The user's
password is never passed directly to SQLCipher. No extension loading is allowed.

Arch and Flatpak execution are documented by the prototypes. Schema and query
APIs are intentionally deferred to Phase 5.

## Consequences

- SQLite transactions, constraints, indexes, and recovery can be reused.
- Native linkage, feature verification, upgrades, and license notices become
  supply-chain responsibilities.
- WAL and shared-memory files reveal write activity and size, but must reveal no
  sensitive plaintext.
- Full memory security may cost latency; disabling it requires measured evidence
  and an explicit documented degraded state.

## Alternatives considered

Plain SQLite plus field encryption risks missed fields, index leakage, and
complex search semantics. An encrypted append-only custom catalog shifts too
much database correctness into this project. Filesystem metadata documents do
not meet transactional and query needs.

## Validation and reversal

The Phase 1 harness committed randomized persistent and temporary canaries,
killed SQLCipher with a live WAL, recovered and checkpointed it, ran cipher and
SQLite integrity checks, verified `temp_store=MEMORY`, rejected a wrong key,
and found no canary in database-related disk artifacts. The installed Flatpak
also opened its pinned SQLCipher 4.18.0 build with a raw key.

Repeated benchmarks, larger catalogs, OS/library memory inspection, and the
complete Phase 5 crash matrix remain required. Any plaintext disk artifact or
unrecoverable WAL behavior reverses this decision; no catalog code may silently
weaken the plaintext-storage invariant.
