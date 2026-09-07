# ADR 0009: Brokered authenticated plaintext for media workers

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Process boundary; Phase 1 prototype 3; Phase 7
- Supersedes: none
- Refines: ADR 0006

## Context

The media helper can either receive one object's DEK and authenticate chunks
itself, or receive only plaintext chunks authenticated by a smaller trusted
broker. The former avoids a plaintext IPC hop but gives codec-adjacent code a
durable object secret. The latter reduces worker authority at the cost of
buffer ownership, IPC, and backpressure complexity.

## Decision

Keep all vault-derived and object DEKs out of media workers. A narrow trusted
broker authenticates each requested encrypted chunk and supplies only bounded
plaintext for the authorized object range over versioned, length-bounded IPC.
Authentication completes before bytes become available to the worker.

Workers receive no vault pathname, catalog access, master-derived key, or
network authority. The final Phase 7 protocol, descriptor passing, shared-memory
strategy, sandbox filters, cancellation semantics, and wipe ownership remain to
be specified and tested.

## Consequences

- A compromised codec worker cannot use an object DEK to decrypt arbitrary
  ciphertext from that object after escaping the intended read protocol.
- The key-bearing trusted computing base is smaller and independent of codec
  libraries.
- Plaintext crosses an IPC boundary and may incur extra copies; every buffer
  needs explicit limits, lifetime ownership, backpressure, and best-effort wipe.
- The broker becomes security-critical and must not parse media formats.

## Alternatives considered

Giving the worker one object DEK was prototyped and limits damage compared with
giving it a master key, but it unnecessarily places a reusable secret beside
hostile native parsers. In-process decoding and giving a worker vault-directory
access remain unacceptable.

## Validation and reversal

Both prototype modes decoded the same approximately ten-second synthetic media,
transported about 265 MiB of RGBA frames, obeyed bounded queues, and recovered
from an injected worker restart. On a 35.2 MiB encoded fixture, elapsed playback
was 9.620 seconds with the object key in the worker and 9.615 seconds with the
broker. A single run is not a benchmark distribution, but it found no material
cost that justifies expanding worker authority.

Phase 7 must test malformed IPC, descriptor spoofing, resource exhaustion,
filesystem/network denial, cancellation, and wipe behavior. Revisit the exact
transport—not the no-key worker goal—if profiling representative media finds an
unacceptable copy cost.
