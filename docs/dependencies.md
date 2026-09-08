# Dependency record

Direct dependencies in the Phase 2 workspace are recorded here alongside the
review checklist. Transitive versions remain pinned by the root `Cargo.lock`.

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
