# Feature glossary

These terms define first-release behavior. Format-level meanings belong in the
future versioned format specifications.

- **Archive import:** bounded listing and selected extraction from ZIP/CBZ,
  7z/CB7, RAR/CBR, or TAR-family input through an isolated helper. The archive
  itself is not a vault object unless explicitly selected as media in a future
  feature.
- **Catalog:** the SQLCipher database containing sensitive metadata,
  relationships, wrapped DEKs, schema state, and operation journals.
- **Cryptographic deletion:** removal of catalog references and wrapped DEKs
  before ciphertext unlink. It does not promise physical erasure.
- **Derived object:** replaceable encrypted output such as a thumbnail or poster,
  with its own object ID and DEK. It is never authoritative over the original.
- **Duplicate:** an import whose content fingerprint matches existing media. The
  user must choose Skip or Import Another Copy; no silent aliasing or merging.
- **Export:** the only user-approved operation allowed to write plaintext media
  to disk outside transient display/playback handling.
- **Favorite:** catalog metadata marking media for filtering or sorting; it does
  not create a copy or gallery membership.
- **Gallery:** a named, ordered container of media and child galleries. Nesting
  is arbitrary within validated depth/size limits and must remain acyclic.
- **Import:** validation, duplicate decision, bounded encryption, durable object
  publication, and transactional catalog insertion for selected source media.
- **Keyfile:** optional bytes combined unambiguously with the password before
  Argon2id. It is an authentication factor, not a backup of the master key.
- **Lock:** revoke active media/helper authority and wipe application-owned
  decrypted state while keeping the process available to unlock again.
- **Media item:** catalog metadata for one immutable imported original and its
  replaceable derived objects.
- **Object:** opaque independently encrypted original or derived bytes stored in
  authenticated, seekable chunks.
- **Offline backup:** a copy of the complete vault directory made only after all
  vault processes close and the catalog is checkpointed.
- **Saved search:** a future versioned query representation stored in the
  encrypted catalog; ad hoc search text need not be saved.
- **Tag:** normalized user metadata related to media (and only to galleries if a
  later UX decision explicitly approves it).
- **Vault:** one directory containing a public unlock header, encrypted catalog,
  opaque encrypted objects, fixed operational directories, and lock state.
- **Viewer:** authenticated image/animation display or video/audio playback; it
  never modifies the original.
- **Writer/reader session:** a writer holds the exclusive vault lock; one or more
  readers may hold shared locks only when no writer exists.
