# Development policy

This policy applies to the Phase 2 production workspace. Prototype-specific
choices remain local to `prototypes/`.

## Toolchain and dependency policy

- Rust 1.98 is the initial minimum supported Rust version (MSRV). Raise it only
  deliberately, record the reason and verification in `ROADMAP.md`, and keep
  dependency resolution compatible with the declared minimum.
- Commit the root `Cargo.lock`. Direct dependencies require the dependency and
  licensing checklist before adoption or material upgrade.
- The Flatpak `cargo-sources.json` pins root-workspace crates by checksum and is
  regenerated from `Cargo.lock` with the reviewed generator commit documented
  in `build-aux/flatpak/README.md`. Review every source/checksum change and
  rerun both dependency policies after an update.
- `cargo deny` rejects unapproved licenses, unknown registries, Git sources,
  wildcard requirements, duplicate versions, and known advisories. Exceptions
  require a scoped reason and review date in the roadmap or a linked ADR.
- Workspace crates inherit the root lint policy. New lint exceptions must be
  narrower than a crate whenever the toolchain permits it and include a reason.

## Logging and diagnostics

Logs may describe public application state, bounded numeric measurements,
opaque error categories, format versions, and non-secret internal operation
identifiers. They must never contain passwords, key material, original names,
tags, search queries, decrypted metadata, media bytes, derived pixels or audio,
vault paths, export paths, IPC plaintext, or attacker-controlled strings.

- Prefer fixed messages and typed error categories over formatting arbitrary
  values. Do not rely on log levels to protect sensitive data.
- Secret-owning and path-owning types must use redacted `Debug` output. Avoid
  derived `Debug` when any field can become sensitive.
- User-facing errors may give recovery guidance but must not be copied directly
  to telemetry or diagnostic logs.
- Tests for new secret containers must exercise formatting and relevant error
  paths. Canary scans must report an artifact identity and match status, never
  the canary value.
- Panic hooks, tracing subscribers, and crash reports are untrusted sinks until
  proven otherwise. Release builds abort on panic and disable core dumps as the
  later secure-runtime phase specifies.

## Unsafe Rust and FFI

Unsafe Rust is denied by default for the workspace. A crate may opt out only
when a required OS or C-library boundary cannot be expressed safely. The
exception must be limited to a small module, document each safety invariant,
and have targeted tests plus sanitizer or Miri coverage where applicable. An
exception that changes a security claim requires a roadmap entry or ADR before
implementation.

## Sanitizer tracing requirements

LeakSanitizer stops a process and inspects its threads through `ptrace`. On the
2026-09-07 managed development runner, `TracerPid` was zero but Yama
`kernel.yama.ptrace_scope` was `1`, seccomp filtering was active, and
`NoNewPrivs` was set. AddressSanitizer worked there, but LeakSanitizer could not
attach. Local smoke commands in that environment therefore set
`ASAN_OPTIONS=detect_leaks=0`; this is a declared loss of leak detection, not a
successful LeakSanitizer result.

Run leak detection on a disposable native Linux host or VM by temporarily
relaxing Yama, then restoring it:

```sh
sudo sysctl -w kernel.yama.ptrace_scope=0
ASAN_OPTIONS=detect_leaks=1 \
  cargo +nightly-2026-09-06 fuzz run secret-canary -- -max_total_time=20
sudo sysctl -w kernel.yama.ptrace_scope=1
```

Do not make `ptrace_scope=0` a permanent workstation setting: while active, it
weakens isolation between processes owned by the same user. CI may use it only
on an ephemeral runner and must restore restricted mode in an `always()` step.
Containerized runs additionally need a seccomp profile that permits the
required tracing calls and sufficient `SYS_PTRACE` capability. Prefer a narrow
profile; `seccomp=unconfined` is acceptable only for a disposable diagnostic
container, never for an application or parser-helper sandbox.

## CI trust boundary

CI triggered by pull requests receives read-only repository permission. It
must not sign, publish, deploy, or receive release secrets. Third-party actions
are pinned to full commit identifiers. Jobs that later require credentials must
not execute untrusted pull-request code.
