# OSV encrypted object format, version 1

## Scope and compatibility

`osv-storage` owns this format. An `.osvo` file contains one original,
thumbnail, or poster as independently authenticated XChaCha20-Poly1305 chunks.
The canonical encoder is the Phase 4 streaming publisher; `ObjectPreamble::parse`
is the allocation-free public framing parser and `ObjectReader` is the
authenticated parser.

Version 1 readers accept only format version 1, suite 1, flags zero, canonical
lengths, and zero reserved bytes. Unknown versions, suites, flags, and reserved
fields fail closed. There is no in-place migration contract: a later incompatible
format uses a new version and derived objects may be regenerated.

The file exposes only its existence, ciphertext length, a 15-byte random nonce
prefix, fixed framing/version values, opaque path, and access/timestamp metadata.
Object identity, role, logical length, chunk geometry, content, and wrapped DEK
remain encrypted. The encrypted catalog is authoritative for vault ID, object ID,
role, logical length, format generation, relative locator, and wrapped DEK.

All integers are unsigned little-endian.

## File layout

The fixed header is 128 bytes, followed by `chunk_count` records:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Magic `OSVOBJ\0\0` |
| 8 | 2 | Object format version, `1` |
| 10 | 2 | Preamble length, `48` |
| 12 | 1 | XChaCha20-Poly1305 suite, `1` |
| 13 | 1 | Mandatory feature flags, zero |
| 14 | 2 | Encrypted-header record length, `80` |
| 16 | 15 | Random object nonce prefix |
| 31 | 17 | Reserved, all zero |
| 48 | 64 | Encrypted immutable header |
| 112 | 16 | Immutable-header authentication tag |

The decrypted immutable header is:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 16 | Random object ID |
| 16 | 1 | Role: original `1`, thumbnail `2`, poster `3` |
| 17 | 7 | Reserved, all zero |
| 24 | 8 | Logical plaintext length |
| 32 | 4 | Plaintext chunk size |
| 36 | 4 | Chunk count |
| 40 | 24 | Reserved, all zero |

Chunk size must be a power of two from 4 KiB through 8 MiB. Logical length is at
most 16 TiB. Empty objects have zero chunks. Otherwise chunk count is exactly
`ceil(logical_length / chunk_size)` and must fit `u32`. Each record is its
plaintext length bytes of ciphertext followed by a 16-byte tag. Every record but
the last has `chunk_size` plaintext bytes. The file length must be exactly
`128 + logical_length + 16 * chunk_count`; trailing bytes and truncation fail.

Chunk `i` starts at `128 + i * (chunk_size + 16)`. Implementations perform all
addition, multiplication, conversions, and seek calculations with checked
arithmetic after validating limits.

## Nonces and authentication

Every object gets a fresh random 32-byte DEK and 15-byte nonce prefix. A nonce is
the prefix, a one-byte domain, and a little-endian `u64` sequence. The immutable
header uses domain `0`, sequence zero. Chunk `i` uses domain `1`, sequence `i`.
This construction makes all nonces under one DEK distinct; randomness failure
aborts before publication.

Header associated data is the literal `osv-ng object header\0v1\0`, the complete
48-byte preamble, vault ID, expected object ID, and role byte. Its immutable
identity is SHA-256 over the serialized preamble, encrypted header, and header
tag.

Chunk associated data is the literal `osv-ng object chunk\0v1\0`, format version,
suite, vault ID, object ID, role, `u32` sequence, `u32` total count, `u32`
plaintext length, and 32-byte immutable-header identity. This binds chunks against
cross-vault/object/role substitution, reordering, replay, and header transplant.
The reader buffers a complete chunk in wipe-on-release memory, authenticates it,
and only then copies plaintext to its caller. Reader and publication results
report the conservative page-lock status of project-owned key/plaintext buffers;
opaque library temporaries remain explicitly reported by `SecurityStatus`.

## Wrapped DEK representation

The catalog representation is exactly 72 bytes: a fresh random 24-byte nonce,
32-byte encrypted DEK, and 16-byte tag. Its XChaCha20-Poly1305 key is the
vault-bound `object-wrapping` purpose key. Associated data is the literal
`osv-ng object DEK wrap\0v1\0`, format version, vault ID, object ID, and role.
Randomness failure aborts; the 192-bit nonce is generated anew for every wrap.

## Paths and durable publication

IDs are lowercase 32-character hexadecimal strings. Originals publish to
`objects/HH/ID.osvo`; thumbnails to `derived/thumbnails/HH/ID.osvo`; posters to
`derived/posters/HH/ID.osvo`; `HH` is the first ID byte. Staging uses
`staging/ID.osvo.part`. Names carry no user metadata.

Directories are mode `0700`; objects are exclusively created mode `0600` through
descriptor-relative, no-follow operations and must be singly linked regular
files. Publication performs: exclusive staging creation; bounded encryption;
file sync; independent authenticated verification; no-replace rename to the
final shard; final-directory sync; staging-directory sync. Newly created
directories and their parents are synced. A descriptor is returned only after
the final object is durable and the expected role/shard/final path is proven to
reach the same inode that the publisher created and authenticated. Interruption
can leave an unreferenced staging or final ciphertext object, never a catalog
reference or plaintext artifact; Phase 6 recovery removes such orphans.

## Fixture and review record

The deterministic test fixture uses plaintext `osv-ng phase four object fixture`,
vault ID `04` repeated 16 times, object ID `07` repeated 16 times, original role,
4 KiB chunks, a sequence-generated DEK beginning at byte 30, and nonce prefix
beginning at byte 62. The SHA-256 digest of its complete 176-byte `.osvo` is
`e32cca3fbe063a0c384fcca58c769b62ada6f8fbdaa5596bd345152ff65235fa`.

The Phase 4 portions of the persistent-format checklist are covered as follows:
canonical framing and compatibility rules are above; all claims are bounded
before allocation; all context and sequence fields are authenticated; plaintext
is released only after tag verification; creation and publication are
descriptor-relative, exclusive, synced, and fault-injected; application-owned
plaintext and DEKs use secure-memory owners; and unit/property/mutation/
truncation/context/short-I/O tests cover the encoder and authenticated reader.
`object-preamble` is an allocation-free fuzz target with a curated seed under
`fuzz/seeds/object-preamble`; it covers public framing, while authenticated-header
and chunk state currently use deterministic mutation/property tests rather than
a key-aware fuzz harness. Publication hooks and subprocess kills cover every
defined persistence boundary, but do not emulate each individual `fsync`/rename
errno. Catalog transactions and sidecar scans, migrations, export behavior, and
orphan recovery belong to Phases 5 and 6 and are not applicable here.
