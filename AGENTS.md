# AGENTS.md

## Project
- `osv-ng` is a greenfield encrypted media vault for modern Linux desktops.
- Rust is the primary language. The supported and tested display path is Wayland; X11/XWayland compatibility is incidental, not a project goal.
- The first release targets Arch Linux development and Flatpak distribution.
- `ROADMAP.md` is the architectural and delivery source of truth. Record material design changes there or in a linked ADR before implementing them.

## Product Scope
- First release: images, video with audio, nested galleries, tags, favorites, search, and ZIP/CBZ, 7z/CB7, RAR/CBR, and TAR-family archive import.
- The UI may be redesigned freely. It must support application themes, user CSS, adjustable gallery layout/density/spacing/type, panel placement, and configurable shortcuts.
- Legacy `.osv` conversion is out of scope for this repository. A separate tool may be built later; do not add compatibility constraints speculatively.
- Executable plugins and user-scripted layouts are not first-release requirements.

## Approved Architecture
- GTK4 via gtk-rs, without requiring libadwaita, is the initial UI direction. Prove it in Phase 1 before treating it as irreversible.
- GStreamer/system codecs are the initial video/audio direction. Codec and archive parsing must be isolated from vault master keys as described in `ROADMAP.md`.
- A vault is a directory containing opaque, independently encrypted original/derived objects plus a SQLCipher catalog.
- Argon2id derives a KEK from password plus optional keyfile. The KEK wraps a random vault master key; password changes rewrap rather than bulk-re-encrypt.
- Derive purpose-specific keys from the master key. Encrypt media objects in authenticated, independently seekable chunks using XChaCha20-Poly1305 and context-bound associated data.
- Give every stored object a random DEK. Store only its wrapped DEK in the encrypted catalog.
- Original names, media types, dimensions, codecs, durations, tags, favorites, gallery structure, and search data must appear only in encrypted storage. Ciphertext counts and sizes may leak.
- Concurrency model: either one exclusive writer or multiple shared readers, never both simultaneously for the first release.

## Security Invariants
- Treat vault files, media, archives, database contents, and sidecars as untrusted input until authenticated and validated.
- Never write plaintext media or sensitive metadata to disk except an explicit, warned export chosen by the user. SQLite temporary storage must be memory-only.
- Never log passwords, key material, original names, tags, queries, decrypted metadata, media bytes, or derived pixels/audio.
- Authenticate every encrypted chunk before release to a decoder. Bind its vault, object, role, format version, and sequence identity in AEAD associated data.
- Keep master/derived/object keys and application-owned plaintext in best-effort locked, non-dumpable, wipe-on-release memory. Report degradation honestly; do not claim control over opaque library or driver allocations.
- Release builds must disable core dumps. Password/keyfile failure paths must wipe partial secret state.
- Filesystem writes must use restrictive permissions, exclusive creation, no-follow/containment checks, atomic rename, required `fsync`, and explicit crash recovery.
- The catalog must never commit a reference to an object that is not already durable. A crash may leave an unreferenced encrypted object, which recovery can remove.
- Secure physical erasure cannot be promised on SSD, copy-on-write filesystems, snapshots, or backups. Delete the wrapped object key before unlinking ciphertext and document this as best-effort cryptographic deletion.
- Decoder/archive helpers receive only the minimum object-scoped authority. They must never receive the vault master key or unrestricted vault-directory access.

## Repository State and Workflow
- Currently there is no production source tree, root Cargo workspace, Flatpak manifest, or CI. Phase 1 experiments are isolated under `prototypes/` and may carry local manifests and commands; do not treat them as Phase 2 project policy. Inspect manifests before running commands.
- Phase 2 must add the exact supported format, lint, test, single-test, audit, fuzz, and Flatpak verification commands to this file after they work locally.
- Document phase progression in `ROADMAP.md` as work advances: keep phase status, delivered scope, verification results, deviations, and follow-up work current in the same change that implements them.
- Develop security and storage behavior test-first. Include fault-injection tests for every multi-step persistent operation.
- Do not silently weaken an invariant to accommodate a library. Record the limitation and gate the affected feature or expose an explicit degraded state.
- Keep this file compact. Put format details, phase history, and acceptance criteria in `ROADMAP.md`; use ADRs for decisions too large for either file.
