# osv-ng Roadmap

## Status

This document defines the approved direction for a greenfield successor to
`obscura-safe-vault`. Only the security lessons and guarantees of the earlier
project are intentionally retained. Source compatibility, its one-file format,
its UI, and legacy-vault migration are not requirements.

Phases 0 and 2 are complete as of 2026-09-07, and Phases 3 and 4 are complete as
of 2026-09-08. Phase 1's five isolated
prototypes passed their automated core paths, and ADRs accept GTK4, GStreamer,
SQLCipher, and brokered authenticated media transport as the initial directions.
Phase 1's manual and representative-media checks below remain explicitly
postponed. They are required evidence before the affected UI, playback, and
Flatpak behavior can be treated as release-ready.

## Product outcome

The first stable release will provide:

- Import and viewing of still and animated images.
- Video playback with audio and seeking.
- Freely nested galleries.
- Tags, favorites, and search.
- Import from ZIP/CBZ, 7z/CB7, RAR/CBR, and TAR-family archives.
- Duplicate detection during import, followed by an explicit user choice.
- A customizable UI: themes, user CSS, grid/list presentation, density,
  spacing, typography, panel placement, and keyboard shortcuts.
- A vault directory that works naturally with ordinary filesystem backup tools
  when the vault is closed.
- Flatpak packaging for modern Linux desktops, developed primarily on Arch
  Linux and tested only on native Wayland sessions.

## Explicit non-goals for the first release

- Windows, macOS, X11, and XWayland-specific development or CI.
- Reading or converting the old `.osv` format. A separate conversion tool can
  be designed after the new format stabilizes.
- Concurrent writing, network filesystems, live multi-device synchronization,
  or conflict-free merging.
- A writer and other reader processes using the same vault simultaneously.
- Executable UI plugins or user-supplied application scripts.
- Editing, transcoding, or modifying original media.
- Hiding the existence, count, or ciphertext size of media.
- Guaranteed physical erasure from flash storage, CoW snapshots, or backups.
- Protection from a privileged attacker controlling an already-unlocked
  process. The design must still reduce the value of individual codec exploits.

## Decisions already made

| Area | Decision | Consequence |
|---|---|---|
| Language | Rust | Memory-safe application core; C FFI remains at GTK, SQLCipher, GStreamer, and codec boundaries. |
| Platform | Modern Linux and Flatpak; Wayland tested | Platform code may use Linux facilities such as `mlock`, `madvise`, `prctl`, `memfd`, Landlock, seccomp, Unix sockets, and file-descriptor passing. |
| UI | GTK4/gtk-rs, no mandatory libadwaita | The app can use accessible native widgets and GSK custom rendering while owning its theme and layout. |
| Media | GStreamer and system/runtime codecs | Avoid rebuilding the codec ecosystem; release review must validate Flatpak codec availability and licensing. |
| Catalog | SQLCipher | Use a relational schema and encrypted pages/journals instead of designing an encrypted database. |
| Originals | One opaque encrypted object per imported media item | Independent backup, deletion, integrity checking, and failure domains. Large objects remain internally chunked for seeking. |
| Derived data | Separate encrypted thumbnail/poster objects | Derived data is replaceable and does not bloat the catalog. |
| Leakage | Counts and ciphertext sizes may leak | Do not add padding solely to hide sizes. Names, types, metadata, relationships, and content must not leak. |
| Authentication | Password plus optional keyfile | Argon2id-derived KEK wraps a random master key. |
| Duplicate handling | Detect, then ask | Never silently skip, merge, alias, or duplicate an import. |
| Concurrency | One writer or multiple readers | Start with an exclusive/shared lock protocol; never allow both modes concurrently. |
| Backup | Offline rsync-style copy | Clean close checkpoints the database. Live backup is not promised in v1. |

## Threat model

### In scope

- An attacker who obtains a closed vault directory, database sidecars, deleted
  file remnants, backups, or filesystem metadata.
- Wrong passwords, missing/wrong keyfiles, modified headers, swapped objects,
  reordered chunks, truncated files, corrupted database pages, and rollback to
  an older backup.
- Malicious images, videos, codec streams, and archives selected for import.
- Process crashes, power loss, disk-full errors, short writes, failed `fsync`,
  and termination between any two persistence steps.
- Accidental partial copies, missing objects, orphan objects, and interrupted
  maintenance.
- Plaintext exposure through swap, core dumps, temporary files, logs, allocator
  residue, clipboard operations, and library-owned buffers.

### Out of scope or bounded

- Root, ptrace-equivalent, kernel, compositor, GPU-driver, or physical-memory
  attacks against an unlocked session can observe displayed/decrypted data.
- Access patterns, vault size, object count, opaque path structure, and object
  ciphertext sizes are observable.
- A complete older backup can legitimately contain media deleted later.
- Anti-rollback guarantees require trusted external monotonic state and are not
  promised. Rollback is detectable only with a newer trusted external record.
- Third-party decoder and driver allocations cannot always be locked or wiped.
  Isolation and honest degraded-state reporting replace an absolute claim.

## Target architecture

### Workspace

The intended dependency direction is inward toward small, UI-independent core
crates:

```text
crates/
  osv-domain/          entities, identifiers, validation, search expressions
  osv-crypto/          KDF, key hierarchy, AEAD, secure memory
  osv-storage/         header, objects, persistence protocol, locking/recovery
  osv-catalog/         SQLCipher connection, schema, queries, migrations
  osv-media/           worker protocol and decoded-media abstractions
  osv-import/          import/archive plans and duplicate decisions
  osv-app/             GTK application, controllers, views, preferences
  osv-test-support/    fixtures, fault injection, temporary vault builders
helpers/
  osv-media-worker/    image/video probing and decode
  osv-archive-worker/  archive listing and extraction
```

`osv-domain`, `osv-crypto`, and the persistent format must not depend on GTK or
GStreamer. SQLCipher-specific code stays behind repository interfaces so tests
can create real encrypted catalogs without leaking it into the UI.

### Process boundary

The main process owns the unlocked catalog, master key, UI, and authorization
decisions. Untrusted parsing happens in short-authority helpers.

A media helper receives only an already-open object descriptor, the selected
object's DEK or a narrowly scoped decrypting channel, immutable framing data,
and IPC endpoints. It never receives the master key, catalog key, arbitrary
pathnames, or general vault access. The archive helper similarly receives one
archive descriptor and emits a bounded, validated listing or selected entry
stream.

Phase 1 compared two practical boundaries:

1. The helper decrypts using an object DEK. This minimizes plaintext copies but
   exposes one object's key to codec-adjacent code.
2. A small trusted broker authenticates/decrypts chunks and streams plaintext
   into the helper. This keeps keys away from codecs but creates an IPC
   plaintext and backpressure problem.

ADR 0009 selects the trusted broker: it authenticates/decrypts bounded chunks
and streams plaintext to a media worker that receives no key. Phase 7 finalizes
the transport and must apply `no_new_privs`, descriptor allowlisting, parent
non-dumpability, resource limits, network denial, and feasible Landlock/seccomp
restrictions. Hardware decode and Flatpak must be tested rather than assumed
compatible.

## Vault directory and formats

### Logical layout

```text
Example.osv/
  vault.header
  catalog.db
  catalog.db-wal       # transient when WAL is active
  catalog.db-shm       # transient coordination state
  writer.lock
  objects/
    4f/
      4f2c...opaque-id.osvo
  derived/
    thumbnails/
      a1/a18d...opaque-id.osvo
    posters/
      9b/9bf0...opaque-id.osvo
  staging/
```

Fixed structural names reveal no user information. Object names are uniformly
random identifiers and are sharded by an identifier prefix only to keep
directory sizes manageable. Original filenames and extensions never appear in
paths. All directories and files are owner-only unless a future explicit
sharing feature changes that policy.

### Plaintext vault header

Version 1 is a fixed 256-byte little-endian structure:

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 8 | Magic `OSVVAULT` |
| 8 | 2 | Vault format version (`1`) |
| 10 | 2 | Header length (`256`) |
| 12 | 2 | Credential-input encoding version (`1`) |
| 14 | 1 | Master-key-wrap suite (`1`, XChaCha20-Poly1305) |
| 15 | 1 | Feature flags (bit 0 means keyfile required; all others mandatory-unknown) |
| 16 | 16 | Immutable random vault ID |
| 32 | 4 | Argon2id memory in KiB |
| 36 | 4 | Argon2id iterations |
| 40 | 4 | Argon2id parallelism |
| 44 | 16 | Random Argon2id salt |
| 60 | 24 | Random XChaCha20-Poly1305 nonce |
| 84 | 32 | Encrypted master key |
| 116 | 16 | Authentication tag |
| 132 | 124 | Reserved authenticated bytes, all zero in version 1 |

The wrap associated data is bytes `0..84` followed by `132..256`; the
ciphertext and tag are excluded. Parsing requires exactly 256 bytes, rejects
nonzero reserved bytes and unknown flag bits, and validates Argon2id bounds
before allocating KDF memory. Accepted version-1 costs are 8 KiB through 1 GiB,
1-10 iterations, and 1-16 lanes, with at least 8 KiB per lane. New vaults use
64 MiB, three iterations, and one lane unless the caller selects another
validated value.

Credential encoding is the literal domain `osv-ng credential input`, one byte
of encoding version, a little-endian `u64` password length and password bytes,
then a little-endian `u64` keyfile length and keyfile bytes. Each component is
capped at 1 MiB. Purpose keys use HKDF-SHA-256 over the master key with the
fixed information prefix `osv-ng subkey\0v1\0`, the 16-byte vault ID, and one
of `catalog`, `object-wrapping`, or `internal`.

The header may expose only what is required to unlock and version a vault:

- Magic, format version, and fixed header length.
- Immutable random vault ID.
- Bounded Argon2id parameters and random salt.
- Whether a keyfile is required.
- Master-key-wrap algorithm/version, nonce, ciphertext, and tag.
- Reserved authenticated extension space.

The wrapped master key's associated data binds the entire immutable header
context, including vault ID, format version, KDF encoding version, and keyfile
requirement. Unknown mandatory features fail closed. Header parsing bounds every
value before allocating or invoking Argon2.

### Key hierarchy

```text
length-prefixed password + optional keyfile
                    |
                 Argon2id
                    |
                   KEK
                    |
          unwraps random master key
                    |
     +--------------+----------------+
     |              |                |
 HKDF catalog   HKDF wrapping    HKDF internal
     key            key              keys
                     |
           wraps random object DEKs
```

- Password and keyfile bytes are unambiguously domain-separated and
  length-prefixed.
- Changing credentials derives a new KEK and rewraps the unchanged master key.
- Each original, thumbnail, and poster gets a fresh random DEK.
- Cross-vault copies decrypt and re-encrypt under a new destination object ID
  and DEK; ciphertext is never transplanted blindly.
- Purpose strings, format versions, and vault identity have stable test vectors.

### Encrypted object

Each `.osvo` is one logical media or derived object. Large files are a sequence
of independently authenticated chunks, allowing bounded-memory import and
random-access video reads.

The provisional structure is:

```text
[fixed preamble: magic, object-format version, framing lengths]
[authenticated encrypted object header]
[chunk 0 record]
[chunk 1 record]
...
```

The encrypted object header contains object ID, logical length, chunk size,
chunk count, and storage framing—not user-visible media metadata. Every chunk
uses a unique nonce and AEAD associated data containing:

- Object-format and crypto-suite version.
- Vault ID.
- Object ID.
- Object role: original, thumbnail, or poster.
- Chunk sequence and total chunk count.
- Immutable header identity or digest.

Physical paths and offsets are not authenticated identities. This permits safe
directory reshaping while preventing cross-vault substitution, role swapping,
and chunk reorder/replay. Authentication completes before bytes leave storage.
Reads have strict caps for chunk size, count, and total length, with checked
arithmetic throughout.

### Encrypted catalog

SQLCipher receives a raw key derived from the vault master key. Do not provide
the user's password directly to SQLCipher. The build must enable in-memory
temporary storage, and connection setup must configure and verify encryption
before any schema access.

Candidate connection policy, finalized by Phase 5 benchmarks and tests:

- Foreign keys enabled.
- WAL mode if crash/performance behavior passes leakage testing.
- `temp_store=MEMORY` plus a build-time memory-only temp-store default.
- SQLCipher page HMAC/integrity protection enabled.
- SQLCipher full memory security enabled unless measured interaction latency is
  unacceptable; any exception must be documented.
- Defensive/trusted-schema settings and bounded busy timeouts.
- A checkpoint on clean close and before documented offline backup.
- No extension loading.

Initial schema areas:

- `vault_state` and `schema_migrations`.
- `objects`: ID, wrapped DEK, role, state, logical size, authenticated format
  generation, and opaque relative locator.
- `media`: original object relation, original name, media class, MIME/format,
  dimensions, duration, codec facts, import time, and content fingerprint.
- `derived_objects`: thumbnail/poster relation, recipe version, dimensions.
- `galleries` and ordered `gallery_children` for arbitrary nesting.
- `tags`, `media_tags`, and optionally `gallery_tags` if approved in the UX spec.
- Favorites and user-visible sort preferences.
- Saved searches only after the query representation is versioned.
- Maintenance/import journal tables for resumable application operations.

Search indexes, including any FTS shadow tables, live in the encrypted database.
Sensitive strings must never become database filenames, attachment names, logs,
or diagnostic output.

## Persistence and recovery protocol

SQLite and filesystem rename cannot share one atomic transaction. The ordering
below makes interruption converge safely.

### Import one object

1. Open the selected source without following an unexpected replacement;
   obtain a stable descriptor where possible.
2. Probe in an isolated worker and compute a duplicate fingerprint that is
   stored only in the encrypted catalog.
3. If a duplicate exists, stop for an explicit Skip or Import Another Copy
   decision. The first release need not implement shared originals.
4. Allocate a random object ID, DEK, and nonces.
5. Exclusively create a restrictive staging file within the vault.
6. Stream-encrypt and authenticate the source in bounded chunks.
7. Flush, `fsync`, close, and verify the completed staged object.
8. Atomically rename it to its final opaque path and `fsync` the containing
   directories.
9. In one SQL transaction, insert the object row, wrapped DEK, media metadata,
   gallery placement, and derived-work request.
10. Generate derived objects through the same durable-object-before-catalog
    rule. Failure here does not invalidate the imported original.

A crash through step 8 can leave only an unreferenced encrypted file. Recovery
may remove it after verifying it is absent from the catalog. A committed row
must never reference an object that was not already durable.

### Metadata mutation

Tags, favorites, names, gallery structure, and saved searches change only in a
SQL transaction. Foreign-key, cycle, uniqueness, and size constraints are also
enforced in application code so corruption produces a controlled error rather
than undefined navigation behavior.

### Delete

1. In one SQL transaction, remove user-visible references and the wrapped DEK,
   and add an opaque cleanup record if needed.
2. Commit the transaction; checkpoint according to the tested deletion policy.
3. Unlink the now-unreferenced original and derived ciphertext.
4. Remove the cleanup record after successful unlink.

A crash leaves at worst inaccessible orphan ciphertext. Startup recovery
finishes unlinking it. Space is returned to the filesystem normally. Physical
overwriting is not guaranteed: flash translation layers, CoW filesystems,
snapshots, old WAL/database pages, and backups may retain ciphertext or an
older wrapped key. Documentation must call this best-effort cryptographic
deletion, never secure erasure.

### Startup recovery

With an exclusive writer lock:

- Validate header and catalog configuration before normal access.
- Resolve database recovery/checkpoint state through SQLCipher/SQLite.
- Enumerate only fixed vault directories with no-follow traversal.
- Remove stale staging files after a conservative operation-state check.
- Reconcile cleanup records and orphan objects.
- Mark catalog entries with missing/corrupt objects as damaged; never silently
  delete their metadata.
- Regenerate missing derived data from authenticated originals.
- Offer a full integrity scan instead of running an expensive scan on every
  open.

Every transition gets deterministic fault injection at each write, flush,
sync, rename, SQL commit, and unlink boundary.

### Locking and backup

- Writer mode takes an exclusive advisory lock for the entire open session.
- Reader mode takes a shared advisory lock. Multiple readers are allowed only
  when no writer holds or can acquire the lock.
- Lock behavior is tested across independent processes, not merely threads.
- A clean writer close checkpoints SQLCipher, wipes state, and releases the
  lock last.
- The supported v1 backup procedure is: close/lock the vault, then copy the
  entire directory with a tool such as `rsync`. Restore is tested from partial
  and complete copies. Live rsync correctness is explicitly unsupported.

## Cross-cutting security invariants

1. No plaintext originals, thumbnails, posters, decoded pixels, audio, names,
   tags, searches, or catalog pages are intentionally written to disk. Explicit
   user-approved export is the only plaintext-media sink.
2. Passwords, keyfiles, KEKs, master keys, derived keys, DEKs, plaintext media,
   and sensitive metadata use wipe-on-release storage owned by the application.
   Page locking and `MADV_DONTDUMP` are best effort and observable.
3. Release processes disable core dumps. Helper processes receive resource
   limits and the narrowest feasible dump/ptrace policy.
4. Authentication precedes parsing. Failed authentication, I/O, allocation, or
   IPC wipes partial plaintext before returning.
5. Randomness failure is fatal to the current operation. Nonces and IDs are
   never substituted with timestamps, weak RNGs, or defaults.
6. No secret or user metadata enters logs, panic messages, tracing spans,
   filenames, process arguments, environment variables, or clipboard without
   an explicit gated action.
7. Vault paths use directory descriptors, exclusive creation, no-follow
   semantics, containment checks, restrictive modes, atomic rename, and
   directory `fsync`; validation followed by a separate path open is not safe.
8. Limits precede allocation/decompression: image dimensions, archive entries
   and expansion ratio, database strings/counts, chunk sizes, media probe work,
   IPC messages, and recursion depth.
9. Unknown format/schema versions fail closed. Migrations are resumable,
   forward-only, backed up, and fault-injection tested.
10. Unsafe Rust and FFI are isolated in small modules with documented safety
    contracts and targeted sanitizer/fuzz coverage.
11. Hardware decoding is optional. Failure falls back to software without
    silently relaxing authentication or isolation.
12. UI lock wipes decrypted models, search results, thumbnails, playback
    queues, clipboard payloads, worker authority, and keys before returning to
    the locked screen.

## UX principles

- The application is keyboard-usable and accessible; customization must not
  remove focus indication or semantic labels by default.
- The gallery is not tied to GNOME visual conventions even though GTK is used.
- First-release customization includes built-in light/dark themes, custom
  colors, user CSS, adjustable density/spacing/typography, multiple gallery
  layouts, panel placement, and configurable shortcuts.
- Invalid user CSS falls back safely to a built-in theme. It cannot load remote
  resources or reveal vault data through generated paths or logging.
- Expensive imports, derived generation, searches, and integrity scans are
  cancellable and report bounded progress.
- Security warnings state the limitation and recovery action. Routine safe
  behavior should not train users to dismiss confirmation dialogs.

## Verification strategy

Phase 2 will establish exact commands and record them in `AGENTS.md`. Intended
gates are:

- Rust formatting and warnings-as-errors linting for the whole workspace.
- Unit, integration, and cross-process tests, including a documented single-test
  command.
- Dependency license/advisory policy suitable for MIT distribution and
  GStreamer plugin variability.
- Property tests for parsers, hierarchy invariants, chunk plans, and recovery
  state machines.
- Cargo fuzz targets for every persistent/untrusted binary format and IPC
  decoder.
- ASan/UBSan coverage for FFI/helper processes and targeted concurrency
  validation where supported.
- Miri for suitable core modules and targeted unsafe abstractions.
- SQLCipher sidecar canary tests proving names, tags, queries, and recognizable
  plaintext never appear in database, WAL, journal, shared-memory, or temp
  artifacts, including after forced crashes.
- A crash matrix that kills a child process at every injected persistence
  boundary and validates cold reopen.
- Hostile archive/media fixtures, decompression bombs, malformed dimensions,
  deep nesting, truncation, chunk swaps, and cross-vault replay.
- Flatpak build/install/run tests on native Wayland where practical.
- Manual release checks for GPU/software playback, audio, portals, scaling,
  theming, accessibility, lock/idle behavior, and restore from backup.

Test fixtures must contain no private user media. Cryptographic formats require
stable known-answer vectors and independent-tool verification where possible.

## Delivery phases

### Phase 0 — Specifications and decision records

**Goal:** Establish reviewable contracts before code fixes accidental formats.

**Progress (2026-09-07)**

- Added the ADR process and records for Rust, the initially proposed SQLCipher
  catalog, independently encrypted objects, vault locking, offline backup, and
  parser isolation. The exact helper transport was deliberately deferred to
  Phase 1.
- Added the threat model with assets, actors, trust boundaries, required
  controls, evidence gates, accepted leakage, and security-claim vocabulary.
- Added the first-release feature glossary, security-relevant user journeys,
  and data-classification/handling rules.
- Added persistent/IPC format review and dependency/licensing checklists.
- Reviewed the documents against the exit criteria below. Open implementation
  choices are bounded Phase 1 experiment questions and do not change prototype
  boundaries; security claims use the defined guarantee, best-effort, accepted
  leakage, and out-of-scope categories.

**Deliverables**

- [ADR template and index](docs/adr/README.md), with ADRs for language, catalog,
  object-store shape, concurrency, supported backup model, and codec/archive
  isolation goal.
- [Threat-model document](docs/threat-model.md) derived from this roadmap.
- [Feature glossary](docs/product/glossary.md),
  [first-release user journeys](docs/product/user-journeys.md), and
  [data classification](docs/product/data-classification.md).
- [Format-review](docs/checklists/format-review.md) and
  [dependency-licensing](docs/checklists/dependency-licensing.md) checklists.

**Exit criteria**

- No unresolved decision changes the feasibility prototypes' boundaries.
- Security claims distinguish guarantees, best effort, accepted leakage, and
  out-of-scope threats.

### Phase 1 — Feasibility prototypes and stack confirmation

**Goal:** Retire high-risk assumptions before building the product.

**Progress (2026-09-07)**

- Implemented all five prototypes under `prototypes/` and documented the Arch
  packages and Flatpak runtimes required to build and exercise them.
- Accepted GTK4/gtk-rs without mandatory libadwaita in ADR 0007. Release-mode
  native-Wayland runs populated 10k/100k models in 1.94/20.22 ms. Continuous
  scrolling at 240 Hz produced p95 frame intervals of 4.18/4.17 ms and
  steady-state RSS of approximately 155/162 MiB.
- Accepted GStreamer in ADR 0008. An application-fed Theora/Vorbis stream
  completed three random seeks in about 0.9-1.8 ms on the host with bounded
  queues, audio, cancellation, and both fake and native output paths.
- Compared object-key and brokered media workers with versioned bounded IPC,
  frame transport, worker-owned audio, hard resource limits, and injected
  restart. A 35.2 MiB synthetic fixture took 9.620/9.615 seconds respectively;
  ADR 0009 selects the broker so codecs receive no object key. Automated tests
  reject malformed initialization, object bounds, and response lengths.
- Accepted SQLCipher in ADR 0002. The raw-key WAL crash/recovery harness found
  no randomized plaintext canary in disk artifacts, recovered after SIGKILL,
  passed cipher/SQLite integrity checks, verified memory-only temp storage and
  wrong-key failure. Across five 10k-row runs, median create/query/checkpoint
  times were 8.45/6.19/4.29 ms with memory security on and 6.92/4.62/4.00 ms off.
- Built and installed the GNOME 50 Flatpak with pinned SQLCipher 4.18.0. Its
  self-test passed Wayland, helper launch, raw-key SQLCipher, sandbox audio, and
  application-fed seekable A/V with three seeks. Permissions are limited to
  Wayland, PulseAudio-compatible audio, DRI, and the desktop portal bus name.
- Recorded runtime codec families, VA/Vulkan hardware candidates, plugin
  licenses, and runtime-license caveats in the Flatpak prototype inventory.

**Postponed Phase 1 checks (still required)**

- Manually verify GTK keyboard/focus and accessibility behavior, user CSS, and
  movement between outputs with different scale factors.
- Measure seek latency, buffering, software fallback, and successful hardware
  negotiation using representative large H.264/H.265/VP9/AV1 media. Synthetic
  registry discovery alone does not satisfy this check.
- Collect repeated helper CPU/RSS/latency samples; current media-boundary
  numbers are feasibility samples, not benchmark distributions.
- Interactively verify the Flatpak portal and visible theming. Replace temporary
  networked Cargo builds with vendored/checksummed sources in Phase 2.

These checks were postponed by project direction on 2026-09-07 so repository
bootstrap could begin. This is a scheduling decision, not a successful result
or a weakening of an exit criterion. Complete and record them before the first
feature depending on the relevant behavior exits its implementation phase, and
in all cases before Phase 17 release qualification.

**Prototypes**

1. GTK4 Rust gallery with thousands of virtualized tiles, custom GSK content,
   keyboard navigation, user CSS, scale-factor changes, and native Wayland.
2. GStreamer playback from an application-supplied seekable byte source,
   including audio, random seeks, cancellation, software decode, and
   opportunistic hardware decode.
3. Playback across the proposed helper boundary, including frame transport,
   audio ownership, worker crash/restart, and bounded queues.
4. SQLCipher opened with a raw derived key in WAL mode, forced-crash recovery,
   checkpointing, integrity checking, temp-store behavior, and artifact scans.
5. Minimal Flatpak exercising Wayland, portals, GStreamer plugins, audio,
   hardware access where permitted, SQLCipher, helper launch, and theming.

**Measurements**

- Scroll/frame latency and memory at 10k and 100k catalog rows.
- Seek latency and plaintext buffering for representative large videos.
- Helper startup/IPC cost and behavior when killed or fed malformed data.
- SQLCipher query/write/checkpoint latency with memory security on and off.
- Flatpak codec coverage and licenses of required runtime extensions.

**Exit criteria**

- ADRs confirm or replace GTK4, GStreamer, SQLCipher, and isolation transport.
- No plaintext canary appears in SQLCipher disk artifacts.
- Seekable video with audio works on Wayland inside Flatpak.
- Failed candidates update this roadmap before Phase 2 proceeds.

### Phase 2 — Repository and quality bootstrap

**Goal:** Make every subsequent phase reproducible and reviewable.

**Completed 2026-09-07**

- Added the root Cargo workspace with the approved eight production/support
  crates and two least-authority helper binaries. Phase 1 prototypes remain
  isolated and are not workspace members.
- Set Rust 1.98 as the initial MSRV, matching the stable Arch toolchain verified
  at bootstrap. The MSRV may be raised only deliberately, with a roadmap entry
  and verification on the new minimum; dependency additions must continue to
  resolve and test at that version.
- Enabled workspace-wide Rust 2024, Clippy `all` at deny level, and
  deny-by-default unsafe Rust. A future crate that needs an exception must opt
  out explicitly and document the smallest unsafe module's safety contract.
- Added the initial fault-injection boundary and redacted secret-canary helpers
  in `osv-test-support`, plus owner-only temporary vault directories and
  property tests for artifact scanning. A cross-process harness now kills a
  child at each reported persistence boundary and verifies the resulting disk
  state from the parent. Root format, lint, test, single-test, advisory-audit,
  and dependency-policy commands are documented in `AGENTS.md` and pass locally.
- Documented logging, diagnostics, unsafe/FFI, dependency, and CI trust
  policies. Added read-only GitHub Actions jobs for the verified workspace and
  advisory/dependency gates; the checkout action and installed tool versions
  are pinned.
- Added a separate, pinned fuzz workspace and CI smoke job. Its first target
  checks the canary scanner under libFuzzer and AddressSanitizer; a local
  six-second run completed about 3.28 million executions without a target
  failure. The managed local runner cannot provide LeakSanitizer's `ptrace`
  access, so that result excludes leak detection and the limitation is recorded
  in the development policy. The CI job temporarily relaxes Yama only on its
  ephemeral VM, enables leak detection, and restores restricted mode afterward.
  This proves the harness only, not coverage of persistent or IPC formats that
  do not exist yet.
- Generated a compact Flatpak source manifest from the root lockfile using a
  pinned revision of the official generator. Flatpak Builder fetches each crate
  by checksum before entering the sandbox; release tests and builds then pass
  with Cargo offline, without checking roughly 24 MiB of raw upstream source
  into this repository. The separate fuzz job remains network-resolved in CI
  and is governed by its pinned lockfile and dependency policy.
- Added a permission-free Phase 2 Flatpak bootstrap manifest using the accepted
  GNOME 50 SDK and Rust extension. It passed all release-mode workspace tests,
  built offline, installed the application and both helpers, and ran all three
  installed binaries. Its temporary ID and empty application entry point are
  explicitly not release packaging or UI/media/portal evidence.
- GitHub Actions run
  [34161201789](https://github.com/Zellione/osv-ng/actions/runs/34161201789)
  passed all five jobs from a clean checkout: workspace format/lint/tests,
  advisory audit, dependency policy, ASan/LeakSanitizer fuzz smoke, and the
  offline Flatpak bootstrap. The first remote run exposed an omitted GNOME
  Platform installation; the workflow now installs the matching Platform and
  SDK explicitly. LeakSanitizer ran with a temporary Yama `ptrace_scope=0` on
  the ephemeral runner, and the job restored restricted mode afterward.

**Deferred follow-up in consuming phases**

- Apply the property, temporary-vault, and cross-process crash harnesses to each
  persistent operation as its production implementation is introduced.
- Add targeted sanitizer/fuzz coverage with each parser or FFI boundary.
- Replace the temporary Flatpak ID and stub with product metadata, permissions,
  and functional GTK/media checks only after those decisions and components
  exist; the Phase 2 workspace packaging gate must remain offline.

**Deliverables**

- Cargo workspace with approved crate boundaries and an MSRV policy.
- `rustfmt`, Clippy warnings-as-errors, test profiles, logging policy, and a
  deny-by-default unsafe policy with narrow exceptions.
- Unit/integration harness, property testing, fault-injection traits, temporary
  vault helpers, and secret-canary helpers.
- CI for format, lint, tests, dependency policy, Flatpak validation, and selected
  sanitizer/fuzz smoke jobs.
- Arch and Flatpak development instructions.
- Exact verification and single-test commands added to `AGENTS.md`.

**Exit criteria**

- A clean checkout passes every documented command.
- CI performs no signing, publishing, or deployment with untrusted PR secrets.

### Phase 3 — Crypto, secure memory, and vault header

**Goal:** Create and unlock an empty vault without catalog or media shortcuts.

**Status:** Complete as of 2026-09-08, including independent security review.

**Delivered**

- `osv-crypto` now owns page-isolated Linux `mmap` allocations that are wiped
  before release, marked `MADV_DONTDUMP`, and best-effort `mlock`ed. Whole-page
  allocation gives every owner independent page-lock accounting; callers can
  observe a truthful aggregate locked/degraded status. Secret bytes, strings,
  fixed keys, passwords, master keys, and derived-key groups redact debug
  output.
- The workspace-wide unsafe-code denial remains in force. Narrowly annotated
  Linux adapters contain the raw-pointer/syscall boundary for secure mappings,
  dump hardening, and descriptor-relative filesystem operations.
- An exact-fill `getrandom` CSPRNG adapter, bounded Argon2id credential
  encoding, XChaCha20-Poly1305 master-key wrapping, HKDF-SHA-256 purpose
  separation, fixed header parser, and deterministic project vectors are in
  place. Argon2id runs in a project-owned non-dumpable, wipe-on-drop mapping;
  failed authentication wipes partially decrypted key state.
- Security status separately reports project-owned page locking and the
  presence of bounded HKDF/HMAC library stack temporaries whose page locking
  and complete wiping cannot be claimed. XChaCha and Poly1305 zeroization
  features are enabled, and process dump hardening bounds the remaining opaque-
  library limitation.
- `osv-storage` can exclusively create and authenticate an empty vault through
  owner-only, `O_NOFOLLOW` and descriptor-relative operations. Header file and
  directory durability are established with file/directory/parent `fsync`.
- Credential changes write and sync `vault.header.new`, preserve
  `vault.header.prev`, atomically rename and sync each namespace transition,
  then remove and sync the backup. Unlock accepts the backup after interruption
  but marks those credentials as recovery-only so they cannot roll back a
  newer current header.
- Creation failures never unlink through a replaceable filesystem name. They
  may intentionally leave an empty private directory or a durable header for
  later explicit recovery rather than risk deleting substituted data.
- All three shipped process entry points, plus vault create/unlock entry points,
  set `RLIMIT_CORE` to zero and clear Linux dumpability before handling secrets.
  Failure is fatal and logged without underlying path or secret data.

**Verification recorded 2026-09-08**

- Workspace format, warnings-as-errors Clippy, and all-target/all-feature tests
  pass. Phase 3 adds 23 crypto/storage unit tests and a subprocess crash test
  that kills rewrap at all seven persistence boundaries.
- Tests cover composed Argon2id/XChaCha20-Poly1305 and HKDF project vectors,
  wrong password/keyfile, authenticated-field tampering, truncation, unknown
  versions/features, oversized KDF cost, randomness and allocation failures,
  wipe-before-unmap, permissions, exclusive creation, symlink rejection,
  unchanged purpose keys after rewrap, and absence of credential/key canaries
  from the durable header. A dedicated fixed-size header-parser fuzz target
  exercises arbitrary input without invoking Argon2; its ASan smoke completed
  21,701,544 executions in 21 seconds without a finding.
- `cargo audit` reports no known vulnerability, and `cargo deny check
  advisories bans licenses sources` passes after recording the cryptographic
  dependency set and its required BSD-3-Clause `subtle` transitive license.
- The regenerated checksum-pinned Flatpak source list passes the complete
  offline Phase 2 release test/build gate, and all three installed hardened
  process stubs execute successfully inside the sandbox.

**Independent review and remediation**

- A GPT-6 Astra independent review initially rejected the gate after reproducing
  two data-loss paths: same-handle retry after an interrupted rewrap, and
  creation-error cleanup through a substituted directory name. It also found a
  false locked-status result, blocking FIFO header opens, and unreported opaque
  HKDF/HMAC temporaries.
- Rewrap handles now become recovery-only immediately after the first namespace
  transition; retry-after-failure is included at every fault point. Creation
  errors perform no deletion. Header reads are nonblocking and require a singly
  linked regular file. Lock aggregation covers credentials and KDF transients,
  and opaque library temporaries have a separate visible status. Poly1305
  zeroization is explicitly enabled.
- The reviewer re-inspected the remediation, reran the 23 focused unit tests and
  seven-boundary subprocess crash test, found no remaining blocker, and approved
  the Phase 3 gate with the nonblocking follow-ups below.

**Deferred follow-up**

- Retain the opaque-library warning in the future vault UI. Add more independent
  primitive vectors, allocation/syscall fault injection, longer sanitizer/fuzz
  campaigns, and user-facing cleanup of incomplete creation artifacts as the
  relevant services and UI arrive.

**Deliverables**

- Secure byte/string/key owners with wipe-on-drop, best-effort page locking,
  page ownership accounting, and `MADV_DONTDUMP`.
- CSPRNG wrapper that cannot return partial randomness.
- Versioned Argon2id password/keyfile encoding with bounded parameters.
- Master-key wrap, HKDF separation, and versioned header parser/writer.
- Owner-only exclusive creation and no-follow open.
- Crash-safe credential rewrap and release core-dump hardening.

**Tests and exit criteria**

- Primitive KATs and project vectors; wrong credentials, tamper, truncation,
  unknown version, oversized KDF cost, RNG/allocation failure, and wipe tests.
- Rewrap fault matrix proves old or new credentials always recover safely.
- Independent review finds no secret in logs, arguments, environment, or disk.

### Phase 4 — Encrypted object store

**Goal:** Persist arbitrary byte streams as independently encrypted, seekable
objects.

**Status:** Complete as of 2026-09-08.

**Delivered scope**

- The final version-one `.osvo` contract is recorded in
  `docs/formats/osvo-v1.md`: fixed canonical framing, encrypted immutable
  header, checked 4 KiB-8 MiB power-of-two chunks, a 16 TiB logical bound,
  exact file-length rules, compatibility policy, and a stable deterministic
  fixture.
- Every object receives a random opaque 128-bit ID, random 256-bit DEK, and
  random nonce prefix. Header and chunk XChaCha20-Poly1305 associated data bind
  format/suite, vault, object, role, sequence/count, plaintext length, and the
  immutable header identity. Header/chunk nonce domains are disjoint and chunk
  sequence nonces are deterministic under the per-object prefix.
- DEKs are wrapped under the vault's purpose-separated object-wrapping key in a
  fixed 72-byte catalog representation bound to vault, object, role, and format.
  The catalog reconstruction API validates public limits before opening files.
- The bounded publisher accepts an exact declared source length, writes only
  encrypted bytes to an exclusively created owner-only staging file, syncs it,
  independently authenticates every chunk, then publishes with a no-replace
  rename and syncs both affected directories before returning its descriptor.
- Original, thumbnail, and poster roles use separate descriptor-relative,
  no-follow namespaces with random-ID sharding. Existing structural components
  must be real directories and object opens require singly linked regular files.
- One authenticated `Read + Seek` implementation supports sequential and random
  access. It allocates at most one validated chunk, decrypts into wipe-on-release
  memory, and never copies a chunk to its caller before tag verification.

**Verification recorded 2026-09-08**

- Workspace format, all-target/all-feature tests, and warnings-as-errors Clippy
  pass. `osv-storage` has 27 unit/property tests plus subprocess kill matrices
  for all seven credential-rewrap and all seven object-publication boundaries.
- Coverage includes empty, one-byte, exact-boundary, multi-chunk, and 16 MiB+
  round trips; sequential/seek equivalence; checked offset properties; declared
  source mismatch; short reads/writes; nonce domain separation; wrapped-key
  context substitution; header/chunk mutation; cross-vault/object/role use;
  chunk swap; truncation; private opaque paths; and plaintext artifact scans.
- The allocation-free `object-preamble` fuzz target completed 26,487,948 ASan
  executions in 21 seconds without a finding. A curated seed corpus is retained
  separately from ignored runtime corpus evolution. The separate fuzz workspace
  formats and checks successfully.
- Workspace and fuzz `cargo audit` report no known vulnerability. Both Cargo
  graphs pass `cargo deny` advisories, bans, licenses, and sources policy.
- The checksum-pinned offline Flatpak manifest passed its complete release test
  and build gate; the installed app, media-worker, and archive-worker stubs all
  execute successfully in the sandbox.

**Independent review and remediation**

- GPT-6 Astra approved the cryptographic format and requested implementation
  changes before accepting the gate. It identified staging-path substitution,
  incomplete decrypted-header lock accounting, an ordinary-stack excess-source
  byte, transient coexistence of two full chunk buffers, and filesystem mutation
  during nominal reads.
- Publication now verifies the writer inode directly and, after rename, proves
  that the expected role/shard/final path reaches that same inode. Reader status
  includes header and wrapping-key owners, the excess-source probe uses secure
  memory, old chunk storage is released before allocating the next full chunk,
  and open-only traversal never creates directories. Regression tests cover each
  remediation, encrypted-header tampering, trailing bytes, and no-replace
  collisions. The reviewer re-inspected these changes before final acceptance.

**Deviations and follow-up**

- Phase 4 can guarantee only that publication returns no catalog reference
  before object durability because Phase 5 owns the encrypted catalog. Phase 6
  will compose that descriptor with a catalog transaction and remove abandoned
  staging/final ciphertext discovered after interruption.
- The authenticated reader protects its internal chunk owner. Later broker/UI
  code remains responsible for using secure destination owners and reporting
  opaque decoder/driver allocation limits; ordinary `Read` callers control the
  memory they supply.
- Public-preamble fuzzing does not yet exercise authenticated header/chunk state,
  and persistence hooks model interruption boundaries rather than every syscall
  errno. Retain deterministic authenticated-parser mutations and add targeted
  lock-failure, symlink/directory substitution, key-aware fuzz, and syscall-fault
  coverage when the shared storage test infrastructure lands.

**Deliverables**

- Final `.osvo` specification, limits, fixtures, and parser.
- Bounded streaming writer with staging, sync, verification, and publication.
- Authenticated random-access and sequential readers.
- Random DEKs, wrapped-key representation, opaque IDs, directory sharding, and
  role-separated derived namespaces.

**Tests and exit criteria**

- Boundary/multi-chunk/large round trips; parser fuzzing; nonce checks; chunk
  swap/reorder/truncate and cross-vault/role substitution; short-I/O faults.
- Property tests cover offset arithmetic and seek equivalence.
- Returned bytes are always authenticated; crashes leave at most removable
  unreferenced ciphertext.

### Phase 5 — SQLCipher catalog and schema

**Goal:** Persist encrypted metadata with relational integrity and migrations.

**Completed 2026-09-09**

- Added an in-process SQLCipher catalog through `rusqlite` 0.40.2's system
  `sqlcipher` feature. Arch resolves the distribution SQLCipher; Flatpak builds
  pinned SQLCipher 4.18.0 with FTS5, `TEMP_STORE=2`, loadable extensions omitted,
  and an explicit `libsqlcipher.so.0` identity so plaintext SQLite cannot satisfy
  the link accidentally.
- Raw 256-bit catalog keys use SQLCipher's binary key API. Its required raw-key
  encoding is assembled only in locked, non-dumpable, wipe-on-drop storage.
  Connection setup verifies SQLCipher and memory-only temp storage before schema
  work, then enables full cipher memory security, foreign keys, WAL,
  `synchronous=FULL`, secure deletion, recursive triggers, bounded busy waits,
  defensive/untrusted-schema modes, and disabled writable attachments and
  double-quoted string literals.
- Added a strict, normalized schema for vault/migration state, objects and
  wrapped DEKs, media facts/fingerprints/favorites, derived objects, ordered
  nested galleries, tags, catalog preferences, versioned saved-search ASTs, and
  operation journals. FTS5 content indexes and triggers keep searchable media
  fields inside the encrypted catalog.
- Added typed opaque IDs and repository transactions for durable-object records,
  media/derived relations, ordered gallery children, cycle rejection, tags,
  favorites, bounded FTS queries, descriptor reconstruction, rollback, and
  clean checkpoints. Forward-only migrations are checksum-recorded and atomic;
  unknown versions and altered migration records fail closed.
- Added cipher/SQLite/foreign-key integrity primitives and a checkpoint primitive
  for the supported closed-vault offline backup workflow.

**Verification recorded 2026-09-09**

- Workspace format, warnings-as-errors Clippy, and all-target/all-feature tests
  pass. The catalog suite has nine integration/crash tests, a connection-policy
  test, and one explicit scale benchmark. It covers constraints and bounds,
  exact Unicode uniqueness,
  Unicode FTS, ordered children, multi-level cycles, transaction rollback,
  descriptor round trips, wrong keys, authenticated page corruption, and
  read-only reopen.
- Deterministic migration faults and real subprocess kills at all three migration
  boundaries recover to the complete schema. A separate post-commit SIGKILL
  recovers its live WAL. Database, WAL, shared-memory, temporary files, and open
  catalog descriptors produced zero plaintext-canary hits before and after clean
  checkpoint.
- The release benchmark verified FTS virtual-index selection at 10k, 100k, and
  1m media rows. Cumulative insert times were 396 ms, 3.563 s, and 59.005 s on
  the development host; the indexed count query remained below 1 ms at every
  size. These are host samples, not portable latency guarantees.
- `cargo audit` found no known vulnerability and `cargo deny` passed advisories,
  bans, licenses, and sources. Native linkage resolves `libsqlcipher.so.0`. The
  checksum-pinned offline Flatpak release test/build gate passed against the
  packaged library, and all three installed stubs execute in the sandbox.

**Deviations and follow-up**

- Phase 5 establishes catalog transactions but does not compose them with Phase
  4 object publication. Phase 6 owns vault locking, durable-object-before-catalog
  orchestration, operation recovery, path-race containment, and orphan cleanup.
- The backup primitive checkpoints and truncates WAL state; v1 deliberately
  supports only a closed/locked whole-directory copy, not SQLite's live backup
  API.
- FTS expressions are currently a bounded repository primitive. Phase 11 owns
  the versioned structured-query parser, Unicode case/normalization UX policy,
  saved-search operations, result cancellation, and application-owned decrypted
  model wiping.
- SQLCipher/SQLite allocations remain opaque. Full cipher memory security is on,
  but only project-owned raw-key encoding has observable locked and wipe-on-drop
  ownership.

**Deliverables**

- Audited SQLCipher build/link strategy for Arch and Flatpak.
- Verified raw-key initialization, defensive pragmas, normalized schema, typed
  repository API, transaction boundaries, and migration runner.
- Cycle prevention, bounded values, ordered children, tag uniqueness, indexed
  search, checkpoint, backup, and integrity primitives.

**Tests and exit criteria**

- Schema constraints, migration interruption, wrong key, corrupt pages, Unicode,
  hierarchy cycles, and query bounds.
- Crash scans of database, WAL, journal, shared-memory, temp files, and open file
  descriptors find no plaintext canaries.
- Benchmarks validate indexes at 10k, 100k, and 1m media rows.

### Phase 6 — Atomic vault service, recovery, and locking

**Goal:** Combine catalog and objects without pretending they share a
transaction.

**Deliverables**

- Import publication, deletion, derived replacement, metadata transactions,
  clean close, startup recovery, operation states, and idempotent repairs.
- Exclusive-writer/shared-readers process locking.
- Missing/corrupt/orphan reporting, maintenance scan, and offline backup/restore.

**Tests and exit criteria**

- Subprocess kill/fault matrix at every filesystem and SQL boundary.
- Disk full, permissions, contention, partial copy, orphan, missing object, and
  corrupt derived/original cases.
- Multiple readers succeed; writer versus reader and writer versus writer fail.
- Recovery converges, and no catalog reference precedes object durability.

### Phase 7 — Media and archive isolation foundation

**Goal:** Put hostile parsers behind a narrow, testable authority boundary.

**Deliverables**

- Versioned length-bounded IPC, child supervisor, descriptor/stream transport,
  sandbox policy, cancellation, deadlines, resource limits, and restart logic.
- Secure transport owners that wipe plaintext and revoke object authority.

**Tests and exit criteria**

- Malformed messages, hangs/crashes, cancellation, descriptor spoofing, protocol
  downgrade, resource exhaustion, and attempted filesystem/network access.
- Sanitizer/fuzz coverage for IPC and FFI.
- Worker cannot open catalog, enumerate vault, obtain master key, use network,
  or retain authority after cancellation within documented platform limits.

### Phase 8 — GTK shell and customization system

**Goal:** Establish the redesigned UI without coupling it to storage details.

**Deliverables**

- Unlock/create/choose flow, lock boundary, navigation/action model, background
  tasks, accessible error handling, and portal-based file/folder selection.
- Built-in themes, safe user CSS/fallback, colors, density, spacing, typography,
  panel placement, shortcut editor, and virtualized gallery/list components.

**Tests and exit criteria**

- Keyboard flows, invalid CSS, scale factors, theme switching, lock during jobs,
  worker failure, portal cancellation, and synthetic 100k-entry performance.
- Lock leaves no accessible decrypted model or worker session.

### Phase 9 — Image import, derived images, and viewer

**Goal:** Deliver the secure still/animated-image path end to end.

**Deliverables**

- Bounded isolated probe/decode, import preview, duplicate decision UI,
  encrypted versioned thumbnails, bounded caches, and a zoom/pan image viewer.
- Display rotation, animation controls, navigation, and an allowlisted metadata
  extraction policy.

**Tests and exit criteria**

- Supported Flatpak formats; malformed files, bombs, huge dimensions, animation
  limits, orientation/color profiles, cache eviction/wipe, and regeneration.
- Decoder receives only authenticated bytes and object-scoped authority.
- Import/view/lock/reopen leaves no plaintext disk artifacts.

### Phase 10 — Video with audio

**Goal:** Deliver bounded, responsive playback from authenticated chunks.

**Deliverables**

- GStreamer source backed by object random access.
- Probe, playback, audio, seek, pause, volume, mute, duration, and end handling.
- Encrypted posters, bounded prefetch/backpressure, cancellation, teardown, and
  hardware decode with automatic software fallback.
- Flatpak codec/driver capability reporting.

**Tests and exit criteria**

- Representative containers/codecs, long/short files, missing audio, corruption,
  repeated seeks, variable frame rate, worker death, device loss, fallback, lock
  mid-playback, and teardown wiping.
- Synchronized playback works on development Wayland and packaged Flatpak.

### Phase 11 — Galleries, tags, favorites, and search

**Goal:** Complete first-release organization and discovery.

**Deliverables**

- Mixed nested galleries; rename, move, reorder, batch selection/edit; tags and
  favorites; cycle/collision rules; structured indexed search; saved searches
  encoded as a versioned AST rather than raw SQL.

**Tests and exit criteria**

- Deep/wide trees, cycles, Unicode/case policy, batch rollback, ordering, parser
  property tests, query limits, and large-result cancellation.
- Operations are catalog transactions, and search state is wiped on lock.

### Phase 12 — Archive import

**Goal:** Import supported archive families without extraction to disk.

**Deliverables**

- ZIP/CBZ, 7z/CB7, RAR/CBR, and TAR-family enumeration in the archive worker.
- Entry selection, path-to-gallery planning, encoding handling, progress,
  cancellation, partial-failure reporting, and direct encrypted staging.
- Explicit policy for password-protected, multipart, nested, linked, sparse,
  special-file, and malformed archives.

**Tests and exit criteria**

- Zip-slip, absolute paths, links/devices, duplicates, deep trees, expansion
  bombs, misleading extensions, corruption, cancellation, and worker crash.
- No archive entry becomes a plaintext file; resource use is bounded.

### Phase 13 — Duplicate detection and import orchestration

**Goal:** Make large mixed imports predictable and recoverable.

**Deliverables**

- Exact duplicate fingerprint computed during streaming and stored only in the
  catalog; explicit Skip/Import Another Copy/apply-to-batch choices.
- Folder/archive queues, bounded parallelism, resumable derived work, itemized
  outcomes, and retry. No deterministic encryption or automatic shared dedupe.

**Tests and exit criteria**

- Same bytes/different names, collision seam, within-batch duplicates,
  cancellation, restart, disk full, mixed sources, and derived concurrency.
- User decisions are never guessed and never lose an original.

### Phase 14 — Export and external boundaries

**Goal:** Add the sole intentional plaintext-to-disk path safely.

**Deliverables**

- Per-action default-cancel warning; selection-only portal or safe-descriptor
  export; exclusive no-follow creation, containment, collision handling,
  bounded writes, partial cleanup, and immediate wipe.
- Clipboard Allow/Warn/Disable policy and best-effort timed sensitive clearing.

**Tests and exit criteria**

- Symlink races, traversal, concurrent collisions, existing-file safety, portal
  revocation, short writes, disk full, cancellation, and wipe observation.
- The checked target is never reopened by path for the write; every plaintext
  sink is explicit, scoped, and documented.

### Phase 15 — Maintenance, integrity, and deletion behavior

**Goal:** Provide honest tools to understand and repair vault health.

**Deliverables**

- Fast/full integrity checks for header, SQLCipher, catalog relations, wrapped
  DEKs, object tags, missing/orphans, and derived recipes.
- Safe derived regeneration, orphan cleanup, storage accounting, deletion-limit
  UI, and validation of restored offline rsync backups.

**Tests and exit criteria**

- Corruption at every layer, wrong key/role/object, partial restore, stale WAL,
  logical deletion remnants, and cancelled repair.
- Maintenance never modifies authenticated originals except explicit delete.

### Phase 16 — Hardening and security review

**Goal:** Challenge the implementation before freezing the format.

**Deliverables**

- Unsafe/FFI inventory and safety contracts.
- Crypto, lifecycle, SQLCipher, filesystem, IPC/sandbox, decoder, archive,
  export, logging, clipboard, and lock-boundary review.
- Sustained fuzz/sanitizer runs, dependency advisory/license review, performance
  DoS budgets, degraded-capability report, and remediation tracking.

**Exit criteria**

- No unresolved critical/high finding.
- Accepted limitations appear in user-facing security documentation.
- Recovery and mutation suites pass before the persistent format freezes.

### Phase 17 — Flatpak and first stable release

**Goal:** Ship a reproducible Wayland-first application.

**Deliverables**

- Minimal Flatpak permissions, portals, codecs/runtime declarations, app
  metadata, icons, desktop entry, and reproducible release build.
- Release hardening, separate debug-symbol policy, dependency inventory/SBOM,
  checksums, signing procedure, and clean-machine install/upgrade tests.
- User docs for credentials, lock, backup/restore, deletion limits, codecs,
  import/export, recovery, accepted leakage, and security boundaries.

**Exit criteria**

- Automated gates and manual Wayland/Flatpak checks pass.
- Backup restore and prior schema upgrade work from release artifacts.
- Release notes do not overstate security guarantees.

## Milestones

| Milestone | Phases | Meaning |
|---|---:|---|
| Architecture validated | 0–1 | Stack and isolation work on Wayland in Flatpak. |
| Storage alpha | 2–6 | Empty vaults and arbitrary objects survive fault injection and recovery. |
| UI/media alpha | 7–10 | Images and video/audio work through the worker boundary. |
| Feature beta | 11–14 | Organization, archive, duplicate, and export features exist. |
| Security beta | 15–16 | Integrity, fuzzing, review, and remediation are complete. |
| Stable release | 17 | Reproducible Flatpak and user/security documentation are ready. |

## Deferred follow-ups

- Standalone old-`.osv` conversion tool after the new format stabilizes. It
  should copy into a new vault and never modify the source.
- Concurrent writer plus readers, live SQLite backup API integration, and
  filesystem-snapshot coordination.
- Multi-device synchronization and conflict resolution.
- Optional padding/privacy modes if size leakage becomes undesirable.
- Similarity-based duplicate detection beyond exact-byte matches.
- Executable plugins, scripts, transcoding, editing, and non-Linux platforms.

## Change control

Changes to the threat model, plaintext policy, key hierarchy, authenticated
identity, persistent formats, catalog encryption, persistence ordering, worker
authority, or concurrency model require an ADR and roadmap/test updates before
implementation. Dependency substitutions require security, maintenance,
license, Flatpak, and isolation review—not merely an API comparison.

Phase completion must update this roadmap with actual commands, measurements,
deviations, and follow-up work. Planned claims must not be silently rewritten as
completed guarantees.
