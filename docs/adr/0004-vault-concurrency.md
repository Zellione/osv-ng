# ADR 0004: Exclusive writer or shared readers

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Concurrency model; Locking and backup; Phase 6
- Supersedes: none

## Context

Filesystem object publication and SQL transactions cannot be one atomic
transaction. Concurrent mutation would multiply recovery states, while typical
first-release use is a single interactive application. Read-only tooling remains
valuable when the vault is not being modified.

## Decision

Use a process-scoped advisory lock held for the complete open session. Writer
mode takes an exclusive lock. Reader mode takes a shared lock. Multiple readers
may coexist; a writer and any other opener may not. Release the lock last after
writer checkpoint/close and secret-state teardown.

The Linux implementation opens an owner-only, singly linked regular
`vault.lock` through an anchored vault-directory descriptor and uses
nonblocking `flock`. Writers durably mark the file dirty before recovery or
mutation and clean only after repair, SQLCipher checkpoint/close, and secret
teardown. Readers open it read-only and never change vault state.

Network filesystems, lock upgrades, concurrent writers, and fairness guarantees
are outside the first release.

## Consequences

- Persistence and recovery state machines remain auditable.
- Background writers and simultaneous read-only viewers are unavailable.
- Lock ownership and contention must be tested with independent processes and
  clearly reported to users.
- Advisory locks do not protect against malicious processes that ignore them;
  all on-disk input is still authenticated and validated.

## Alternatives considered

An application daemon with IPC centralizes writing but adds lifecycle and
authority complexity. Multi-writer optimistic concurrency conflicts with the
object/catalog publication protocol. Exclusive-only access unnecessarily blocks
safe read-only tooling.

## Validation and reversal

Phase 6 proved reader/reader success and reader/writer plus writer/writer
exclusion across independent processes, including lock release after process
kill. Broader concurrency requires a new persistence model and superseding ADR.

The initial Phase 6 implementation is not yet accepted: independent review
found that object readers can retain decryption authority after their service
session closes and its lock is released, and that the current SQLCipher reader
creates WAL/SHM sidecars. The Phase 6 blocker record in `ROADMAP.md` governs
remediation and re-review.
