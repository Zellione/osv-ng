# osv-ng Roadmap

## Status

This document defines the approved direction for a greenfield successor to
`obscura-safe-vault`. Only the security lessons and guarantees of the earlier
project are intentionally retained. Source compatibility, its one-file format,
its UI, and legacy-vault migration are not requirements.

No implementation stack is final until the Phase 1 prototypes pass. The
expected stack is Rust, GTK4, GStreamer, SQLCipher, and Flatpak on Wayland.

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
| UI | GTK4/gtk-rs candidate, no mandatory libadwaita | The app can use accessible native widgets and GSK custom rendering while owning its theme and layout. |
| Media | GStreamer and system codecs candidate | Avoid rebuilding the codec ecosystem; validate Flatpak codec availability and licensing. |
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

Phase 1 must compare two practical boundaries:

1. The helper decrypts using an object DEK. This minimizes plaintext copies but
   exposes one object's key to codec-adjacent code.
2. A small trusted broker authenticates/decrypts chunks and streams plaintext
   into the helper. This keeps keys away from codecs but creates an IPC
   plaintext and backpressure problem.

Select the design with the smaller auditable trusted computing base. In both
cases, apply `no_new_privs`, descriptor allowlisting, parent non-dumpability,
resource limits, network denial, and feasible Landlock/seccomp restrictions.
Hardware decode and Flatpak must be tested rather than assumed compatible.

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

The exact byte layout will be specified and test-vector-backed before Phase 3
is complete. It may expose only what is required to unlock and version a vault:

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

**Deliverables**

- ADR template and ADRs for language, catalog, object-store shape, concurrency,
  supported backup model, and codec/archive isolation goal.
- Threat-model document derived from this roadmap.
- Feature glossary, first-release user journeys, and data classification.
- Format-review and dependency-licensing checklists.

**Exit criteria**

- No unresolved decision changes the feasibility prototypes' boundaries.
- Security claims distinguish guarantees, best effort, accepted leakage, and
  out-of-scope threats.

### Phase 1 — Feasibility prototypes and stack confirmation

**Goal:** Retire high-risk assumptions before building the product.

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
