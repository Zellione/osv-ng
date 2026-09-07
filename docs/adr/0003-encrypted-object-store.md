# ADR 0003: Independently encrypted object store

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Vault directory and formats; Phase 4
- Supersedes: none

## Context

Media can be large, needs random access, and must survive partial backup and
independent corruption. A monolithic vault amplifies failures and makes seeking,
repair, and incremental backup difficult. Plain paths and filenames would leak
sensitive metadata.

## Decision

Store each original, thumbnail, and poster as its own opaque object. Give every
object a random identifier and random DEK; store only the wrapped DEK in the
encrypted catalog. Encrypt object content as bounded, independently
authenticated XChaCha20-Poly1305 chunks. Associated data binds format version,
vault ID, object ID, role, chunk sequence/count, and immutable header identity.

Publish objects durably before committing catalog references. Authenticate a
chunk fully before releasing its plaintext. Exact byte layouts, limits, nonce
derivation, and test vectors remain Phase 3/4 decisions.

## Consequences

- Backup, verification, recovery, derived replacement, and cryptographic
  deletion have object-sized failure domains.
- Counts, opaque directory structure, access patterns, and ciphertext sizes
  remain visible and are accepted leakage.
- Object overhead and catalog/object reconciliation are required.
- Physical erasure is not promised; deleting the wrapped DEK before ciphertext
  unlink is best-effort cryptographic deletion.

## Alternatives considered

A single encrypted container worsens random access and failure isolation.
Whole-file AEAD requires full-object buffering or cannot safely seek. Convergent
encryption would leak equality and conflicts with explicit duplicate handling.

## Validation and reversal

Phase 4 tests must cover chunk substitution, reorder, replay, truncation,
cross-vault/role swaps, arithmetic bounds, short I/O, and crash publication.
Format implementation cannot begin until the Phase 3 format contract and vectors
are reviewable.
