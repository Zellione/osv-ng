# Dependency record

Direct dependencies in the production workspace are recorded here alongside the
review checklist. Transitive versions remain pinned by the root `Cargo.lock`.

## Phase 3 cryptographic and Linux dependencies

- `argon2` 0.5.3 provides the RustCrypto Argon2id implementation. Default
  features are disabled; its zeroization feature is enabled, and the project
  supplies a wipe-on-drop, non-dumpable working matrix rather than using the
  convenience heap allocation.
- `chacha20poly1305` 0.10.1 provides RustCrypto XChaCha20-Poly1305 authenticated
  encryption. Default features are disabled and only allocation support is
  enabled. A direct `poly1305` 0.8.0 declaration enables zeroization for its
  transitive authenticator state.
- `hkdf` 0.12.4 and `sha2` 0.10.9 provide RustCrypto HKDF-SHA-256 key
  separation.
- `getrandom` 0.3.4 is the sole production CSPRNG backend and is wrapped by an
  exact-fill project interface.
- `zeroize` 1.9.0 supplies compiler-resistant wipe operations with default
  features disabled; its derive macro is deliberately not included.
- `libc` 0.2.189 exposes Linux memory, descriptor-relative filesystem,
  descriptor-passing, polling, resource-limit, dumpability, Landlock, and
  seccomp syscalls within narrowly allowed unsafe adapters.

These direct crates are `MIT OR Apache-2.0`. Their versions, features, sources,
MSRV, and known advisories were reviewed through package metadata, the lockfile,
`cargo audit`, and `cargo deny`. The cryptographic graph also requires
`subtle` 2.6.1 under BSD-3-Clause; that permissive license is explicitly added
to both dependency-policy files. Upgrade review must rerun project vectors, the
rewrap kill matrix, unsafe-boundary review, advisory audit, and dependency
policy gates.

Phase 7 adds no external production dependency. `osv-worker-protocol` uses the
already-reviewed `zeroize`, while `osv-isolation` composes the already-reviewed
`libc`, `zeroize`, and project crypto/protocol crates. This avoids a serializer
or sandbox wrapper on the hostile protocol and syscall surfaces.

## `proptest` 1.11

- Scope: development dependency of `osv-test-support`; it is not shipped.
- Need: generate and shrink inputs for parser, arithmetic, hierarchy, recovery,
  and test-helper properties required by the verification strategy.
- Provenance: crates.io package from the
  [proptest project](https://github.com/proptest-rs/proptest), locked at 1.11.0
  initially and compatible with the workspace MSRV.
- License: `MIT OR Apache-2.0` according to crate metadata; either choice is
  compatible with the project's MIT distribution.
- Features: default features are disabled. Only `std` is enabled; fork,
  timeout, macro, hardware-RNG, and unstable features are unnecessary.
- Exposure: test inputs only. The crate is not linked into production binaries,
  does not receive vault keys or user data, and adds no release-time authority.
- Maintenance: review advisories, license metadata, MSRV, feature changes, and
  repository activity before upgrades. Remove it if the property suite moves to
  another maintained generator.

## `libfuzzer-sys` 0.4.13

- Scope: fuzz-workspace runtime only; it is not shipped.
- Need: link Rust fuzz targets to LLVM libFuzzer with sanitizer coverage.
- Provenance: crates.io package from
  [rust-fuzz](https://github.com/rust-fuzz/libfuzzer), exactly pinned at 0.4.13
  in the separate fuzz workspace.
- License: `(MIT OR Apache-2.0) AND NCSA` according to crate metadata. All three
  permissive terms are allowed only in the fuzz-workspace policy.
- Exposure: public/generated fuzz inputs only. Fuzz corpora must never contain
  user media, metadata, vaults, credentials, or key material.
- Maintenance: update deliberately with `cargo-fuzz`, rerun the smoke target and
  dependency policies, and review build-script changes before adoption.
