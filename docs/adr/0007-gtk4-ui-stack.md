# ADR 0007: GTK4 as the initial UI stack

- Status: Accepted
- Date: 2026-09-07
- Owners: project maintainers
- Roadmap links: Decisions already made; Phase 1; Phase 8
- Supersedes: none

## Context

The desktop needs accessible native interaction, large virtualized galleries,
custom rendering, user CSS, configurable layout, and a supported native Wayland
path. Requiring libadwaita would constrain application-owned theming without
being necessary for those capabilities.

## Decision

Use GTK4 through gtk-rs as the initial application UI stack. Do not require
libadwaita. Use GTK models and widgets for semantics, focus, selection, and
keyboard behavior, with narrowly scoped GSK snapshot rendering where custom
tile content materially helps.

This accepts the stack, not the Phase 1 prototype as production code. Phase 8
must independently implement and test the application shell and accessibility.

## Consequences

- GTK supplies Wayland integration, input semantics, accessibility hooks, and
  virtualized list/grid machinery.
- The project owns more visual styling and adaptive layout behavior than an
  application built around libadwaita.
- Custom snapshots must not replace accessible widget semantics.
- X11 and XWayland behavior remains incidental.

## Alternatives considered

Qt and a fully custom renderer were credible alternatives. They were not
selected because the GTK prototype met the scale and customization needs while
retaining native widget semantics. Mandatory libadwaita was rejected as an
unnecessary constraint, though individual compatible components may be used
later through a new decision.

## Validation and reversal

On native Wayland, release builds populated 10,000 rows in 1.94 ms and 100,000
rows in 20.22 ms. During continuous automated scrolling at 240 Hz, both sizes
had approximately 4.17-4.18 ms p95 frame intervals; steady-state RSS was about
155 MiB and 162 MiB respectively. The 100,000-row run had a 16.67 ms maximum
interval after its first sample period.

Manual keyboard/focus, accessibility inspection, and mixed-scale-output checks
remain release gates and are tracked in the roadmap. Reverse this ADR if those
checks expose defects that cannot be corrected without abandoning GTK's model
or rendering architecture.
