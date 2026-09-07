# ADR 0006: Object-scoped parser isolation

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Process boundary; Phase 1 prototype 3; Phase 7
- Supersedes: none
- Refined by: ADR 0009

## Context

Images, video, audio, and archives are hostile inputs parsed by large native
dependency stacks. The main process owns the unlocked catalog and master key, so
parsing those formats there would expose excessive authority after a decoder
compromise.

## Decision

Run media and archive parsing in supervised helper processes with versioned,
length-bounded IPC and minimum object-scoped authority. Helpers never receive
the master key, catalog key, unrestricted vault paths, or network access.
Cancellation revokes descriptors/channels and terminates helpers that do not
cooperate.

Phase 1 compared (a) providing one object DEK to a helper and (b) keeping keys
in a small broker that authenticates chunks and streams plaintext. ADR 0009
selects the brokered design so codec workers receive no key. Frame transport,
audio ownership, backpressure, hardware decode, and sandbox primitives remain
bounded implementation and validation concerns.

## Consequences

- A codec exploit is constrained to one authorized object within documented OS
  and driver limits.
- IPC, supervision, buffer ownership, sandbox policy, and degraded-state
  reporting add complexity.
- Driver and opaque library allocations cannot be promised locked or wiped.
- Authentication must precede decoder access in the selected design.

## Alternatives considered

In-process decoding has the smallest IPC cost but unacceptable authority.
Giving helpers a vault path or master-derived key makes the process boundary
mostly cosmetic. Permanent privileged workers retain authority too long.

## Validation and reversal

Phase 1 measured both authority candidates, bounded queues, crash/restart,
malformed framing, audio, and software paths; ADR 0009 records the resulting
transport decision. Phase 7 must prove denial of vault enumeration, catalog
access, networking, and post-cancellation authority and complete representative
hardware/software validation.
