# ADR 0011: Pure-Rust decoding for the initial image path

- Status: Accepted
- Date: 2026-09-13
- Owners: project maintainers
- Roadmap links: Security architecture; Phase 9
- Supersedes: none

## Context

Phase 9 needs bounded decoding of PNG, JPEG, GIF, and extended WebP after the
broker has authenticated source bytes. The earlier GTK/GdkPixbuf experiment
introduced native transfer buffers whose wiping and allocation behavior the
application could not control and, in Flatpak, could delegate to a separate
glycin subprocess outside the project's worker protocol.

## Decision

Use `image` with default features disabled and exactly the PNG, JPEG, GIF, and
WebP features enabled. Decode and encode only in the short-lived confined media
helper. Keep an allocation-free broker-side structural/resource probe as an
early rejection layer; the helper independently performs the real decode.

Derived thumbnails are versioned PNG objects. JPEG EXIF orientation is applied
before scaling. Profile presence is allowlisted metadata only: version 1 does
not transform ICC, sRGB, gamma, or chromaticity data. GTK displays the helper's
sRGB-assumed PNG result and never decodes an original.

## Consequences

- The supported image formats equal the explicitly enabled decoder features;
  BMP, ICO, PNM, QOI, and TIFF are not accidentally claimed.
- Rust reduces, but does not eliminate, decoder risk. Third-party decoder
  working allocations are not application-owned protected memory and cannot be
  promised locked or wiped; confinement, resource limits, and process exit are
  the controls for those allocations.
- Embedded profiles are detected but not honored in recipe version 1. Images
  requiring exact color management may render differently, and the UI must not
  claim colorimetric accuracy.
- The broker validates the returned PNG structure, CRCs, dimensions, and recipe
  header before encrypted publication.
- `image::Limits::max_alloc` is non-strict. In `image 0.25.10`, PNG forwards the
  400 MiB value to `png`'s decoder byte limit, GIF reserves its canvas and frame
  buffers against it, and JPEG retains it in the zune decoder options. WebP's
  default `ImageDecoder::set_limits` checks dimensions but does not account its
  internal allocations against `max_alloc`. The preliminary pixel/frame limits
  and the helper's 1 GiB address-space ceiling therefore remain authoritative
  for WebP and backstop every decoder. This is a documented degraded resource
  guarantee, not a claim that opaque allocations are exactly bounded.

## Alternatives considered

GdkPixbuf was rejected for this path because its native and delegated transfer
buffers do not fit the explicit protected-memory and worker-authority model.
Glycin integration may eventually provide stronger desktop format coverage but
would require a reviewed nested sandbox/protocol design. A custom decoder set
would substantially increase format-specific security code.

## Validation and reversal

The Phase 9 corpus exercises genuine PNG, JPEG, GIF, and extended-WebP decode,
malformed structures and PNG CRCs, resource ceilings, all eight EXIF
orientations, and sRGB/ICC presence under the no-transform policy. Flatpak and
dependency-policy gates remain release requirements.

Reconsider this decision if the enabled decoders cannot enforce allocation
ceilings, the required animation behavior cannot be implemented within the
worker limits, or a reviewed glycin interface can preserve the same authority,
memory-reporting, and cancellation guarantees.
