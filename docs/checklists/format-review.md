# Persistent and IPC format review checklist

Complete this checklist before accepting a new format or incompatible version.
Attach the completed review to its specification or ADR; `N/A` needs a reason.

## Scope and ownership

- [ ] The format owner, trust boundary, purpose, and authoritative specification
  are named.
- [ ] Security-sensitive versus public fields and accepted leakage are listed.
- [ ] A canonical encoder and parser entry points are identified.
- [ ] The compatibility policy, current version, and mandatory/optional feature
  rules are explicit.
- [ ] Unknown versions and unknown mandatory features fail closed.

## Framing and bounds

- [ ] Magic, version, lengths, counts, byte order, and reserved bytes have exact
  widths and canonical encodings.
- [ ] Every length/count is bounded before allocation, I/O, KDF work, recursion,
  decompression, or conversion to a platform-sized integer.
- [ ] Addition, multiplication, offsets, and chunk/record calculations use
  checked arithmetic with specified maximums.
- [ ] Truncation, trailing bytes, duplicate fields, non-canonical encodings,
  invalid Unicode, and zero/empty edge cases have defined outcomes.
- [ ] Streaming parsers use bounded memory and do not trust seekability or file
  size as authenticity.

## Cryptographic binding

- [ ] Algorithm/suite and derivation versions are encoded and authenticated.
- [ ] Key purpose, vault ID, object ID, role, immutable header identity, sequence,
  and total count are domain-separated or explicitly justified as inapplicable.
- [ ] Nonce uniqueness has a construction, bound, and testable failure policy;
  randomness failure aborts the operation.
- [ ] Authentication completes before plaintext is returned, parsed, displayed,
  decoded, or written to an export sink.
- [ ] Error behavior does not distinguish sensitive authentication facts or
  release unauthenticated partial plaintext.
- [ ] Stable known-answer and negative vectors cover tamper and context swaps.

## Persistence and filesystem behavior

- [ ] Creation uses restrictive modes, exclusive creation, directory-relative
  containment/no-follow operations, and no user metadata in paths.
- [ ] Publication order identifies each write, flush, file sync, rename,
  directory sync, SQL transaction, checkpoint, and unlink boundary.
- [ ] A catalog reference cannot commit before the referenced object is durable.
- [ ] Recovery after interruption at every boundary is deterministic,
  idempotent, and conservative about user metadata.
- [ ] Partial copies, old sidecars, missing/corrupt files, and rollback have
  documented behavior.
- [ ] Migration is forward-only, resumable, bounded, backed up where required,
  and does not leave a partially interpreted old format.

## Secret and metadata handling

- [ ] No protected value enters plaintext files, temp storage, filenames, logs,
  tracing, panic text, argv, environment, or clipboard implicitly.
- [ ] Application-owned plaintext/keys use wipe-on-release memory and the
  documented best-effort page protections.
- [ ] SQLCipher settings are configured and verified before schema access;
  database, WAL, journal, SHM, temp artifacts, and open descriptors are scanned.
- [ ] Export is an explicit, scoped, warned sink with collision/cancellation
  behavior.

## Verification and review

- [ ] Unit, property, mutation, truncation, cross-context, and boundary tests
  cover both encoder and parser.
- [ ] Parser and IPC decoder fuzz targets include a seed corpus and size/time
  caps; regressions become fixtures.
- [ ] Fault injection covers short read/write, allocation/randomness failure,
  disk full, sync/rename/commit/unlink failure, and child-process kill.
- [ ] Independent tools or implementations verify crypto vectors where feasible.
- [ ] Unsafe/FFI code has a written safety contract and targeted sanitizer/Miri
  coverage where applicable.
- [ ] The threat model, roadmap, recovery documentation, and data classification
  agree with the final format and its limitations.
