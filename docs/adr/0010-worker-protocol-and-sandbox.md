# ADR 0010: Short-lived brokered worker sessions

- Status: Accepted
- Date: 2026-09-10
- Owners: project maintainers
- Roadmap links: Process boundary; Phase 7
- Supersedes: none
- Refines: ADR 0006 and ADR 0009

## Context

Media and archive parsers need authenticated plaintext without gaining vault
keys, vault paths, catalog access, network access, or authority that survives a
request. The boundary must reject ambiguous framing and downgrade attempts,
remain bounded when either peer is hostile, and work inside Flatpak's outer
sandbox. Codec threads and explicitly brokered device descriptors must remain
possible in later media phases.

## Decision

Use one short-lived process and one private Unix stream per object-scoped
request. The broker creates the stream before `exec`, places only its worker end
on standard input, clears the inherited environment, nulls standard
output/error, and gives the child a
parent-death signal. The worker closes every descriptor above 2
before accepting protocol traffic. Cancellation shuts down the channel, waits
for a short grace period, then kills and reaps the process. Seccomp permits
thread-style clones needed by codec runtimes but denies process-style clones,
namespace escape, and execution, so no unsupervised descendant can remain.
Startup retry is bounded by policy and never applies beyond the handshake.

Protocol v1 has a fixed eight-byte magic and 24-byte header containing a fixed
wire version, message kind, reserved byte, little-endian payload length, and
64-bit request identity. Payloads are limited to 1 MiB. Hello/ready negotiation
must select v1 without downgrade; start, ordered data, end, cancellation, and
terminal messages are checked by state. Data sequence numbers begin at zero.
Diagnostics carry only public failure classes.

The trusted broker authenticates object chunks before constructing a
`PlaintextBuffer`. That owner uses the project's locked, non-dumpable,
wipe-on-release allocation and exposes bytes only for synchronous transport.
Wire encoding writes directly into a locked or explicitly degraded,
non-dumpable, wipe-on-release allocation without an intermediate plaintext
allocation. Worker receive buffers are bounded and wiped after use. The
worker receives bytes, never a vault descriptor or key. `SCM_RIGHTS` support is
limited to exactly one regular-file, pipe, or Unix-socket descriptor and rejects
directories and multiplicity; it is reserved for narrowly scoped plaintext or
output channels, not vault-directory authority.

Before ready, the worker disables dumps, sets `no_new_privs`, caps core/file
output, descriptors, address space, CPU, and stack, and installs a
seccomp filter. The filter validates the syscall architecture and denies new
network endpoints, filesystem opens/enumeration/path inspection, execution,
pathname and descriptor mutation syscall families, new process-style clone
variants, and sandbox/process-group escape operations.
Thread-style `clone` remains available for codec runtimes. An empty Landlock
ruleset additionally denies handled filesystem access when the running kernel
supports it. Ready reports individual enforcement flags. The broker requires
all mandatory flags and exposes Landlock absence as a degraded state rather
than pretending it succeeded.

## Consequences

- Parser compromise has no reusable key, pathname, catalog handle, network
  socket, or channel after cancellation.
- Per-request process startup and plaintext IPC add latency and copies. The
  protocol applies kernel backpressure and one absolute operation deadline.
  Cancellation uses one best-effort nonblocking frame and starts its independent
  grace deadline before transmission, so a full send buffer cannot extend worker
  authority to the operation deadline.
- Landlock is defense in depth because kernels or outer sandboxes may not offer
  it. Seccomp, descriptor closure, limits, and `no_new_privs` are mandatory.
- Seccomp is a narrow deny policy rather than a syscall allowlist so GStreamer
  and archive libraries can still use ordinary memory, synchronization, and
  thread operations. Future device access must be opened and allowlisted by the
  broker before this policy is installed.
- Library, kernel, GStreamer, and driver-owned copies cannot be proven locked or
  wiped. This ADR only describes project-owned buffers.

## Alternatives considered

`SOCK_SEQPACKET` preserves messages but has smaller platform-dependent packet
limits and does not remove the need for explicit length validation. Shared
memory reduces copies but creates a more complex revocation and wipe protocol.
Long-lived worker pools retain authority and state across objects. Namespace
creation is not reliably available inside unprivileged Flatpak processes.
Giving the worker an object DEK remains rejected by ADR 0009.

## Validation and reversal

Unit and subprocess tests cover every frame truncation, oversized payloads,
identity and sequence changes, descriptor types, real media/archive sessions,
startup and operation hangs, bounded restart, downgrade, false sandbox claims,
and attempted file and network access. The wire decoder is a dedicated fuzz
target. ASan exercises framing and descriptor FFI; sandboxed subprocess tests
run without ASan because its shadow mapping exceeds the intentional address
space limit. Workspace dependency and Flatpak gates remain required.

If representative Phase 9/10 workloads show unacceptable copying, add a
broker-owned sealed-memory transport under a new protocol version. Do not move
keys into the worker or weaken authenticated-before-release ordering.
