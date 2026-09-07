# Threat model

This document turns the roadmap security requirements into a review contract.
It describes the first-release design, not a claim that unfinished code already
provides these protections.

## Protected assets

| Asset | Required property |
|---|---|
| Password and optional keyfile | Confidential; never persisted or logged by the application |
| KEK, master key, derived keys, DEKs | Confidential, purpose-scoped, wipe on release |
| Original and derived media plaintext | Confidential except while deliberately displayed, played, or exported |
| Names, media facts, tags, favorites, galleries, and searches | Confidential at rest and in diagnostics |
| Catalog/object relationships | Confidential at rest; consistent after recovery |
| Encrypted chunks and catalog records | Authenticated before use; corruption reported |
| User intent | Destructive, export, and duplicate choices must be explicit |

Availability matters, but must never be recovered by bypassing authentication or
silently discarding metadata.

## Adversaries and capabilities

### Closed-vault attacker

Can copy, inspect, modify, reorder, truncate, replace, roll back, or partially
restore every vault file and sidecar. Can observe names of fixed structural
paths, object counts, ciphertext sizes, timestamps, and backup remnants. Cannot
break the selected primitives or guess a strong credential within its intended
work factor.

### Hostile-content author

Controls selected images, video/audio streams, archives, filenames, embedded
metadata, dimensions, entry graphs, compression ratios, and malformed framing.
Attempts code execution, resource exhaustion, path traversal, parser confusion,
and persistence through derived data.

### Local unprivileged process

Can contend for advisory locks and may attempt IPC spoofing, descriptor misuse,
process inspection allowed by the OS, or interaction with exported desktop
surfaces. It cannot legitimately read owner-only vault files or bypass OS access
control.

### Operational failure

Power loss, process kill, disk full, short I/O, failed sync/rename/unlink,
allocation failure, and partial copy may occur between any persistence steps.

## Trust boundaries

1. The main process is trusted with credentials, vault keys, authenticated
   plaintext, catalog state, authorization decisions, and the UI.
2. Crypto and persistence modules are smaller trusted components inside the
   main process. Their formats and transitions require dedicated review.
3. Media and archive helpers are untrusted parser compartments. They receive
   only bounded IPC plus one object-scoped descriptor/key or plaintext stream.
4. GTK, SQLCipher, GStreamer, codecs, allocators, the compositor, audio stack,
   GPU drivers, and the kernel are external dependencies with differing access
   to transient plaintext. Claims about their buffers are bounded honestly.
5. The vault directory, import sources, archives, catalog, sidecars, backups,
   IPC messages, and helper output are untrusted inputs until validated at the
   responsible boundary.

## Required controls

### Offline confidentiality

- Argon2id derives a KEK from an unambiguous length-prefixed password/keyfile
  encoding and bounded parameters.
- The KEK wraps a random master key; purpose-specific keys derive from it, and
  random per-object DEKs are wrapped only in the encrypted catalog.
- Sensitive catalog data exists only in SQLCipher storage configured and tested
  for encrypted pages, journals/WAL, and memory-only temporary storage.
- Original/derived bytes are independently encrypted. Plaintext disk writes are
  limited to an explicit warned export.

### Integrity and substitution resistance

- Authenticate headers and chunks before allocating from their claims or
  releasing plaintext to a parser.
- Associated data binds vault, object, role, format version, header identity,
  chunk sequence, and count.
- Unknown mandatory format/schema versions fail closed. Checked arithmetic and
  explicit limits precede reads, allocations, recursion, and decompression.
- Missing or corrupt referenced objects are marked damaged, never silently
  removed from the catalog.

### Persistence and crash safety

- Use owner-only directories/files, directory-relative no-follow operations,
  exclusive creation, atomic rename, required file/directory sync, and explicit
  recovery states.
- Make ciphertext durable before a catalog reference commits. Crashes may leave
  inaccessible/orphan ciphertext, never a committed reference to unpublished
  content.
- Delete wrapped DEKs transactionally before unlinking ciphertext. Describe the
  result as cryptographic deletion, not physical erasure.
- Inject deterministic failure at every persistent transition and validate a
  cold reopen in a child process.

### Runtime exposure reduction

- Application-owned secrets and plaintext use wipe-on-release owners with
  best-effort page locking and `MADV_DONTDUMP`; degradation is observable.
- Release processes disable core dumps. Logs, panics, arguments, environment,
  filenames, and tracing exclude secrets and sensitive user metadata.
- Helpers use descriptor allowlists, bounded messages/queues, deadlines,
  resource limits, network denial, `no_new_privs`, and feasible Landlock/seccomp
  controls. Authority ends on cancellation or worker termination.
- Locking the UI first revokes workers and output channels, then clears decoded
  models, playback state, clipboard payloads, and keys before showing locked UI.

## Threats and required evidence

| Threat | Control | Evidence gate |
|---|---|---|
| Offline password guessing | Bounded, versioned Argon2id | KATs, benchmarked parameters, wrong-input tests |
| Header downgrade or allocation bomb | Fixed bounds; authenticated version/features | Parser properties and fuzzing |
| Cross-vault/object/role/chunk substitution | Context-bound AEAD | Negative vectors and mutation tests |
| Catalog plaintext in WAL/temp/crash files | SQLCipher policy and artifact canaries | Forced-crash scans on Arch and Flatpak |
| Catalog refers to absent object | Durable-object-before-transaction ordering | Fault/kill matrix at every boundary |
| Symlink/path traversal | Descriptor-relative containment and no-follow opens | Hostile filesystem tests |
| Archive bomb or path escape | Bounded isolated listing/extraction | Malformed/bomb fixtures and resource limits |
| Codec compromise reaches vault/master key | Object-scoped helper authority | Sandbox and access-denial tests |
| Worker retains data after cancellation | Revocation, bounded queues, termination | Cancellation/crash tests and buffer accounting |
| Secret retained in app-owned memory | Locked/non-dumpable wipe owners | Unit tests and targeted process inspection |
| Lock race corrupts state | Exclusive writer/shared readers | Independent-process contention tests |
| Rollback to complete old vault | No v1 anti-rollback guarantee | Explicit user documentation only |

## Accepted leakage and bounded claims

- Vault existence, fixed structure, ciphertext counts and sizes, timing, access
  patterns, and opaque identifiers are observable.
- A complete old backup can reveal content and keys valid at that older point.
- SSD translation layers, CoW filesystems, snapshots, and backups defeat a
  physical-erasure guarantee.
- Root, ptrace-equivalent actors, a hostile kernel/compositor/driver, and
  physical-memory attacks against an unlocked session can observe plaintext.
- Opaque library, decoder, audio, and driver allocations may not be lockable or
  wipeable. The application reports the strongest state it can actually prove.
- Anti-rollback needs trusted external monotonic state and is not promised.

## Security-claim vocabulary

- **Guarantee:** enforced by design and covered by a release-blocking test.
- **Best effort:** attempted, observable, and allowed to degrade with a warning.
- **Accepted leakage:** intentionally outside confidentiality goals and clearly
  documented.
- **Out of scope:** no mitigation is promised for the stated actor/capability.

Any implementation limitation that changes these categories requires a roadmap
update or ADR before the affected feature is enabled.
