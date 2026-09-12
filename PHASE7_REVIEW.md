# Phase 7 review

- Review date: 2026-09-12
- Branch: `phase-7-isolation-foundation`
- Reviewed commits: `cf7c7f6..75d17fc`, including the review remediation in
  `75d17fc` (`fix phase 7 isolation review findings`)
- Result: three findings remain.

## 1. [P1] Workers can still signal other processes

Location: [crates/osv-isolation/src/sandbox.rs:257](crates/osv-isolation/src/sandbox.rs#L257)

The seccomp deny policy blocks `kill`, `tkill`, and `tgkill`, but leaves
`rt_sigqueueinfo` and `rt_tgsigqueueinfo` available. A compromised worker can use
these alternate syscalls to signal other processes permitted by normal Linux
signal permissions, including the broker.

A temporary probe using the actual `apply_worker_sandbox` implementation
successfully invoked `rt_sigqueueinfo` with `SIGTERM` against a disposable
sibling process. The syscall returned zero and the sibling exited from
`SIGTERM`.

Requested remediation: deny the alternate signal syscalls and add a subprocess
regression verifying that a sandboxed worker cannot signal a disposable peer.

## 2. [P1] Plaintext still passes through unprotected heap allocations

Locations:

- [crates/osv-isolation/src/supervisor.rs:190](crates/osv-isolation/src/supervisor.rs#L190)
- [crates/osv-isolation/src/transport.rs:110](crates/osv-isolation/src/transport.rs#L110)
- `decode_message` in [crates/osv-worker-protocol/src/lib.rs](crates/osv-worker-protocol/src/lib.rs)

`Supervisor::send_authenticated` copies the protected plaintext into an ordinary
`Vec` with `plaintext.as_slice().to_vec()` before protected wire encoding.
`FramedChannel::receive` and `decode_message` likewise allocate ordinary vectors
for incoming plaintext. These application-owned copies do not receive the
best-effort memory locking and non-dumpable allocation protection required by
the security invariants. Wiping them on release does not prevent swapping while
they exist.

In addition, the temporary `SecretBytes` allocation used for wire encoding can
have degraded page locking, but its lock status is discarded rather than
reported to the caller. The allocation-free encoder regression covers only
`encode_into`, not these surrounding allocations or degradation reporting.

Requested remediation: retain protected storage throughout the send, receive,
and decode paths, and propagate transient encoding-buffer lock degradation.
Add coverage for the complete transport path and forced lock degradation.

## 3. [P2] Descriptor validation accepts network sockets

Location: [crates/osv-isolation/src/transport.rs:327](crates/osv-isolation/src/transport.rs#L327)

`receive_descriptor` accepts any descriptor whose `fstat` type is `S_IFSOCK`.
This does not enforce the documented restriction to Unix sockets: Internet
sockets have the same file type.

A temporary probe passed a loopback UDP socket through `send_descriptor` and
confirmed that `receive_descriptor` accepted it. When the reserved descriptor
transport is used, it can therefore convey network authority despite the
sandbox restrictions on creating network sockets.

Requested remediation: for socket descriptors, require `SO_DOMAIN == AF_UNIX`
and reject other domains. Add a regression passing an Internet socket through
`SCM_RIGHTS` and asserting rejection.

## Verification

The following targeted test command passed all 16 tests:

```sh
cargo test -p osv-isolation -p osv-worker-protocol -p osv-media-worker -p osv-archive-worker
```

Additional temporary probes confirmed the signal-policy bypass and acceptance
of an Internet socket descriptor. The plaintext findings are based on source
inspection. The review did not rerun the full workspace, Flatpak, audit, or fuzz
gates and did not modify production code or repository tests.

## Remediation verification

- Remediated: 2026-09-12.
- GPT-6 Astra re-review result: approved with no blocking security or
  correctness findings.
- The re-review verified queued and pidfd signal denial, protected writable
  plaintext ingress and transport/decode ownership, worker fail-closed lock
  degradation reporting, supervisor error-path observability, protocol v2
  status validation, and Unix socket-domain descriptor enforcement.
- Workspace formatting, warnings-as-errors Clippy, full workspace tests, the
  exact debug-redaction canary, `cargo audit`, and production dependency policy
  checks pass after remediation.
