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

Phase 6 must prove reader/reader success and reader/writer plus writer/writer
exclusion across processes, including crashes. Broader concurrency requires a
new persistence model and superseding ADR.
