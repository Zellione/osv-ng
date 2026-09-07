# Data classification

Classification follows information sensitivity, not whether bytes are presently
encrypted. Decrypted values retain their original class in memory and IPC.

| Class | Examples | At-rest rule | Diagnostics/IPC rule |
|---|---|---|---|
| Secret key material | Password, keyfile bytes, KEK, master/derived keys, DEKs | Never persist except approved wrapped keys/header inputs | Never log or place in argv/env; object DEK only if the selected helper design explicitly permits it |
| Sensitive content | Original bytes, thumbnails, posters, decoded pixels/audio | Encrypted objects only; explicit warned export is the exception | Never log; IPC only over bounded object-scoped channels; wipe app-owned buffers |
| Sensitive metadata | Original names, MIME/type, dimensions, codec/duration, fingerprints, tags, favorites, galleries, searches, import time | Encrypted catalog only | Never log; validate/bound across UI/helper boundaries |
| Sensitive operational state | Wrapped DEKs, object relationships, journal records, corruption details tied to media | Encrypted catalog only | Prefer opaque IDs and non-sensitive error categories |
| Public format/bootstrap data | Magic, versions, header length, vault ID, KDF parameters/salt, keyfile-required flag, wrap nonce/ciphertext/tag | May appear in authenticated plaintext header | May diagnose bounded versions/parameters, never credentials |
| Accepted filesystem leakage | Vault existence, fixed paths, opaque IDs, counts, ciphertext sizes, timestamps | Unhidden by design | Document, do not enrich with sensitive labels |
| Non-sensitive application data | Built-in theme IDs, generic settings, binary/version, aggregate prototype timing | May persist outside vault | May log if it cannot be correlated with sensitive user data |

## Handling rules

- Classification survives copies, derived representations, errors, crash state,
  and serialization. A thumbnail is sensitive content, not disposable public
  cache data.
- Use stable opaque IDs only where correlation is necessary; do not include them
  in routine logs if aggregate counters suffice.
- Test canaries are synthetic sensitive values and must receive the same storage
  handling as the class they test.
- User CSS and shortcut settings are non-sensitive only while they contain no
  vault-derived values. Remote CSS resources are prohibited.
- Explicit export declassifies only the bytes and destination the user approved;
  catalog metadata and keys remain protected.
