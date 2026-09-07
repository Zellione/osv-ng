# GTK gallery feasibility prototype

This is Phase 1 experiment code, not the production application shell. It tests
GTK4/gtk-rs on native Wayland with a virtualized `GtkGridView`, custom GSK
snapshot content, keyboard navigation, user CSS, scale-factor changes, and
basic model/frame/RSS telemetry.

## Prerequisites

- Rust 1.92 or newer (gtk4-rs 0.11 MSRV; the project MSRV remains a Phase 2 decision).
- GTK 4.12 or newer and its development metadata.
- A native Wayland session.

See the [consolidated Arch and Flatpak prerequisites](../README.md) for exact
system packages. Rust installation policy is intentionally deferred to Phase 2.

## Run

From this directory:

```sh
cargo run --release -- --items 10000 --css sample.css
cargo run --release -- --items 100000 --css sample.css
cargo run --release -- --items 100000 --css sample.css --auto-scroll-seconds 10
```

Use the arrow, Page Up/Down, Home/End, and Enter keys to exercise native grid
navigation and activation. Move the window between outputs with different
scale factors when available. The status row and stdout report model creation,
resident memory, and five-second frame-interval samples. Scroll continuously
during a sample; idle windows may not receive frame ticks.

`--auto-scroll-seconds` continuously traverses the virtualized grid and closes
the window after the bounded measurement interval. It makes repeatable frame
sampling possible without synthesizing input events; use native keys separately
to validate focus and selection behavior.

The frame metric is presentation interval, not input-to-presentation latency.
A full latency capture needs compositor presentation timing and is follow-up
work before this prototype can pass Phase 1.

## Test

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Record the GPU, compositor, display scale, release build commit, row count,
model population time, steady-state RSS, p95/max frame interval, and any visual
or input defects. Do not compare debug-build performance.
