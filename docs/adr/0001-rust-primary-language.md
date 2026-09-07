# ADR 0001: Rust as the primary language

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Decisions already made; Phase 2
- Supersedes: none

## Context

The application handles secrets and hostile binary inputs while integrating
with GTK, SQLCipher, GStreamer, Linux process controls, and file-descriptor
APIs. Memory safety in application-owned code materially reduces risk, but C
libraries and FFI remain inside the trusted computing base.

## Decision

Use stable Rust as the primary implementation language. Isolate `unsafe` and
FFI in small modules with explicit safety contracts. Keep format, crypto, and
domain crates independent of GTK and GStreamer. Phase 2 will select and enforce
an MSRV rather than treating the current developer toolchain as the policy.

## Consequences

- Rust ownership and types support bounded buffers and explicit secret owners.
- gtk-rs and GStreamer Rust bindings avoid most handwritten FFI.
- Rust does not make C dependencies, codecs, allocators, drivers, or unsafe
  blocks memory-safe; isolation and targeted sanitizer coverage remain needed.
- Contributors need a reproducible Rust and native-library toolchain.

## Alternatives considered

C and C++ provide direct native-library access but expand memory-safety review.
Go complicates GTK integration and precise secret-memory ownership. A mixed
language core would add build and audit boundaries before a demonstrated need.

## Validation and reversal

Phase 1 must prove usable GTK/GStreamer/SQLCipher bindings. If a binding blocks
a required feature, prefer a narrow reviewed FFI adapter. Replacing Rust as the
primary language requires a superseding ADR and a revised threat analysis.
