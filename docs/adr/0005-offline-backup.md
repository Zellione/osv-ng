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

The Phase 6 service makes that state machine-checkable: clean writer close
durably records a nonsensitive clean marker after checkpoint and teardown;
writer open records dirty before recovery or mutation. Its offline copy helper
takes the exclusive lock, requires the clean marker, follows no symlinks, copies
only directories and singly linked regular files with restrictive exclusive
creation, and syncs the completed tree. Interrupted destinations are preserved,
must be treated as incomplete, and receive normal restore/open validation.

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

Phase 6 tested complete and interrupted copies, busy and dirty source rejection,
missing objects, and cold restore. A future live-backup design requires a
superseding ADR and explicit generation consistency.

The Phase 6 remediation replaces lexical descendant checking with opened
filesystem-identity ancestry comparison before destination creation. Relative,
`..`, and symlink-aliased descendant regression cases fail closed. This change
awaits the independent gate re-review recorded in `ROADMAP.md`.
