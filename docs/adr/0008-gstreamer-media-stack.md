# ADR 0008: GStreamer as the initial media stack

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Decisions already made; Phase 1; Phase 10
- Supersedes: none

## Context

Video playback needs audio, seeking over authenticated application-supplied
bytes, bounded queues, cancellation, hardware acceleration with software
fallback, and practical codec availability in Flatpak. Directly integrating a
codec collection would enlarge project-owned unsafe and format-specific code.

## Decision

Use GStreamer as the initial media pipeline. Encoded bytes enter through a
random-access application source; GStreamer and its plugins receive no vault
path or unrestricted object access. Keep encoded and decoded queues bounded,
and treat hardware acceleration as optional with a software fallback.

Codec/runtime selection remains distribution policy. Registry presence is not
evidence that hardware negotiation succeeds for a representative stream.

## Consequences

- The project reuses GStreamer's demuxing, decoding, synchronization, seeking,
  Wayland, and audio integration.
- Plugin availability, licenses, patents, runtime updates, and native-library
  security become explicit release-review responsibilities.
- Decoder isolation remains necessary because GStreamer and codecs process
  hostile input.
- Opaque plugin, driver, and audio allocations cannot be included in absolute
  plaintext-memory or wiping claims.

## Alternatives considered

Direct FFmpeg integration offers lower-level control but requires more custom
pipeline, synchronization, seeking, hardware, and sandbox integration. A
Rust-only codec stack does not currently cover the first-release format and
hardware requirements.

## Validation and reversal

The host prototype decoded a synthetic Theora/Vorbis Ogg through `GstAppSrc`,
completed three random seeks in roughly 0.9-1.8 ms, and exercised both fake and
native Wayland/PipeWire sinks with bounded queues. The installed Flatpak
completed seekable video with audio and reported software and hardware decoder
candidates; its exact inventory is recorded with the prototype.

Representative large H.264/H.265/VP9/AV1 media, forced software fallback, and
successful hardware playback remain follow-up gates. Reverse this ADR if the
supported Flatpak cannot provide legally distributable baseline codecs or if
application-fed random access cannot meet real-media seek and memory bounds.
