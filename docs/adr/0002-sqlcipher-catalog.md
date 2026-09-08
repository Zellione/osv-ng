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

Phase 5 uses `rusqlite` 0.40.2 with its system `sqlcipher` feature. Arch links
the distribution library. Flatpak builds the checksum-pinned SQLCipher 4.18.0
source as `libsqlcipher.so.0`, with an explicit SONAME and `sqlcipher.pc`, so a
generic platform `libsqlite3` cannot satisfy the dependency accidentally. The
Flatpak build enables FTS5 and memory-only temporary storage and compiles out
loadable extensions.

The application calls SQLCipher's binary key API through one documented FFI
function. SQLCipher's `x'<hex>'` raw-key encoding is assembled in locked,
non-dumpable, wipe-on-drop memory, so the derived catalog key is neither treated
as a password nor rendered into an ordinary Rust string. Connection setup then
verifies `cipher_version`, memory-only temp storage, and foreign keys before any
schema work. It keeps cipher full-memory security enabled and applies WAL,
`synchronous=FULL`, authenticated pages, secure deletion, bounded waits,
defensive mode, untrusted-schema mode, disabled double-quoted strings, and
disabled writable `ATTACH` behavior.

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

Phase 5 repeated the canary scan through ordinary commits, a forced crash with a
live WAL, and forced crashes at every migration boundary. Database, WAL,
shared-memory, temporary artifacts, and catalog-related open descriptors had no
canary hits; recovery, wrong-key rejection, page-corruption rejection, cipher
integrity, SQLite integrity, and foreign-key integrity passed. An indexed
release benchmark passed at 10k, 100k, and 1m media rows. The complete packaged
workspace test gate passed inside GNOME 50.

SQLCipher and SQLite still own opaque decrypted page/cache allocations. Full
memory security is enabled, but the application cannot promise those allocations
are page-locked or directly wipe-observable. Any plaintext disk artifact or
unrecoverable WAL behavior reverses this decision; no catalog code may silently
weaken the plaintext-storage invariant.
