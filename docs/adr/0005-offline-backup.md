# ADR 0005: Closed-vault directory copy backup

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Backup; Locking and backup; Phase 6
- Supersedes: none

## Context

Users need ordinary filesystem backup without trusting a custom cloud service.
Copying while SQLCipher or object publication is active can combine catalog and
object generations that never formed a valid vault state.

## Decision

Support backup only while the vault is cleanly closed and unlocked by no
process: checkpoint, close, and then copy the entire vault directory with a tool
such as `rsync`. A restored copy is treated as untrusted and runs normal open and
recovery validation. Live filesystem copies and network-filesystem semantics are
not supported in v1.

## Consequences

- Backup uses common tools and opaque ciphertext only.
- The application must expose clear close/checkpoint state and restoration
  diagnostics.
- Ciphertext deleted from the active vault may remain in backups, along with an
  older catalog containing its wrapped key.
- A partial copy may be detected as damaged; it is not silently repaired by
  deleting metadata.

## Alternatives considered

Live `rsync` cannot atomically snapshot SQLCipher and independent objects.
Filesystem snapshots are not portable and may retain deleted secrets. An online
backup protocol would need a consistent-generation manifest and is deferred.

## Validation and reversal

Phase 6 must test complete and interrupted copies, missing objects, stale
sidecars, and cold restore. A future live-backup design requires a superseding
ADR and explicit generation consistency.
