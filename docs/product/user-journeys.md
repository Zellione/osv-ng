# First-release user journeys

Each journey names its security-relevant completion and failure behavior. UI
layout is deliberately unconstrained.

## Create and unlock a vault

1. The user chooses a new directory, password, and optional keyfile.
2. The app explains keyfile dependence and recovery limitations before commit.
3. It creates an owner-only header, random vault/master keys, and encrypted
   empty catalog using crash-safe publication.
4. On later open, it bounds header parameters before KDF work, authenticates the
   header/master-key wrap, opens the catalog with its derived raw key, and
   acquires the requested lock mode.

Wrong credentials, missing keyfiles, unsupported versions, lock contention, and
damage are distinct errors without sensitive diagnostics. Partial secrets are
wiped after every failure.

## Import files and handle duplicates

1. The user selects files through a desktop portal or explicit picker.
2. An isolated helper probes only selected descriptors under resource limits.
3. The app shows a bounded import plan without writing source names to logs or
   vault paths.
4. For each fingerprint match, the user chooses Skip or Import Another Copy.
5. Originals become durable encrypted objects before their metadata transaction
   commits; derived generation follows independently and can be retried.

Cancellation revokes worker authority and removes only verified unreferenced
staging artifacts. Existing media remains unchanged.

## Import an archive

1. The archive helper receives one archive descriptor and emits a bounded,
   validated listing.
2. The user reviews/selects entries using normalized display names that are
   never trusted as filesystem paths.
3. Selected entries follow the normal duplicate and import flow.

Unsupported encryption, bombs, traversal names, deep nesting, malformed input,
timeouts, and helper crashes fail individual work without exposing the vault.

## Browse, organize, and search

1. After unlock, the user browses image/video thumbnails in customizable grid or
   list layouts and navigates nested galleries with keyboard or pointer.
2. The user edits tags, favorites, ordering, and gallery relationships through
   catalog transactions that enforce bounds and prevent cycles.
3. Search runs against encrypted-catalog indexes; queries and results never enter
   logs or plaintext files.

Changing layout, theme, CSS, typography, spacing, panels, or shortcuts cannot
change storage semantics or remove accessible focus by default.

## View images and play video

1. The main process authorizes one object and authenticates chunks before
   decoder access.
2. A helper decodes with bounded queues; the UI renders images/animation or
   synchronized video/audio and supports random seeks and cancellation.
3. Hardware decode is opportunistic. A software fallback must preserve the same
   authentication and isolation boundary.

A failed seek, codec, helper, or derived object reports a recoverable error. It
does not expose another object or silently weaken sandboxing.

## Lock and close

1. Lock stops playback/import, revokes helpers, clears clipboard content owned
   by the app, wipes decoded models/caches and keys, then shows locked UI.
2. Clean writer close checkpoints SQLCipher, finishes required recovery state,
   wipes secrets, closes storage, and releases the lock last.
3. A reader closes without mutation.

If teardown cannot establish the documented state, the app reports degradation
and terminates helpers rather than claiming a clean lock.

## Export

1. The user selects items and an explicit destination.
2. The app warns that plaintext will be created outside the vault and may be
   retained by the target filesystem, backups, or applications.
3. It authenticates source chunks and writes only to that authorized destination
   with safe collision handling and cancellable progress.

No preview, drag, clipboard, or helper side effect may become an implicit export.

## Delete, maintain, back up, and restore

1. Delete removes user-visible relations and wrapped DEKs transactionally, then
   unlinks inaccessible ciphertext through resumable cleanup.
2. Integrity scan authenticates referenced objects, reports missing/corrupt
   originals, regenerates derived objects, and conservatively identifies orphans.
3. Backup requires a cleanly closed vault; the user copies the whole directory.
4. Restore opens a copy as untrusted input and reports incomplete generations or
   damage without silently dropping catalog records.

Deletion is described as best-effort cryptographic deletion. Old backups and
storage remnants may retain decryptable older state.
