# osv-ng

`osv-ng` is a greenfield encrypted media vault for modern Linux desktops. Rust,
GTK4, GStreamer, SQLCipher, native Wayland, and Flatpak are the accepted initial
stack.

The repository has completed Phase 6. It contains the production cryptographic,
encrypted object-store, SQLCipher catalog, and atomic vault-service foundations,
plus the archived Phase 1 feasibility prototypes. The postponed manual Phase 1
checks remain required before release qualification; see
[ROADMAP.md](ROADMAP.md) for detailed status and verification records.

## Build and test the Phase 2 workspace

The initial minimum supported Rust version (MSRV) is 1.98. Install the pinned
policy tools:

```sh
(cd /tmp && cargo install cargo-audit --version 0.22.2 --locked)
(cd /tmp && cargo install cargo-deny --version 0.20.2 --locked)
(cd /tmp && cargo install cargo-fuzz --version 0.13.2 --locked)
rustup toolchain install nightly-2026-09-06 --profile minimal
```

Then run the production workspace gates from the repository root:

```sh
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo audit
cargo deny check advisories bans licenses sources
cargo audit --file fuzz/Cargo.lock
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml \
  check advisories bans licenses sources
ASAN_OPTIONS=detect_leaks=0 \
  cargo +nightly-2026-09-06 fuzz run secret-canary -- -max_total_time=20
```

The Flatpak manifest uses a generated, checksum-pinned source list and disables
networking inside its build sandbox. Policy tool installation is kept separate
from project dependency resolution.

Verify the workspace inside the Flatpak SDK without build-time networking:

```sh
flatpak-builder --force-clean --disable-rofiles-fuse \
  .flatpak-phase2 \
  build-aux/flatpak/io.github.osv_ng.Phase2.yml
flatpak-builder --run .flatpak-phase2 \
  build-aux/flatpak/io.github.osv_ng.Phase2.yml osv-app
flatpak-builder --run .flatpak-phase2 \
  build-aux/flatpak/io.github.osv_ng.Phase2.yml /app/libexec/osv-media-worker
flatpak-builder --run .flatpak-phase2 \
  build-aux/flatpak/io.github.osv_ng.Phase2.yml /app/libexec/osv-archive-worker
```

This is a workspace bootstrap gate, not distributable application packaging.
The temporary Flatpak ID grants no runtime permissions and does not decide the
release application ID.

The workspace now provides a tested headless vault service; the end-user media
pipeline and GTK application arrive in later phases. Development and diagnostic
rules are in [docs/development-policy.md](docs/development-policy.md), and direct dependency decisions are in
[docs/dependencies.md](docs/dependencies.md).

## Supported development environment

- Arch Linux development host;
- native Wayland session (X11 and XWayland are not supported test paths); and
- x86-64 GNOME 50 Flatpak runtime for the current smoke manifest.

## Arch Linux prerequisites

Install the compiler toolchain, native libraries, test codecs, database, and
packaging tools:

```sh
sudo pacman -S --needed \
  base-devel pkgconf rustup \
  gtk4 \
  gstreamer gst-plugins-base gst-plugins-bad gst-plugin-pipewire \
  gst-plugins-good gst-plugins-ugly gst-libav \
  sqlcipher \
  flatpak flatpak-builder
rustup default stable
```

For hardware-video testing, install the driver appropriate for the machine. The
tested AMD path uses `mesa`, `libva`, and `libva-utils`; current Intel hardware
normally also needs `intel-media-driver`. NVIDIA setup depends on the selected
proprietary or open driver stack. Hardware decode is optional and must fall back
to software decoding.

Verify the host setup:

```sh
rustc --version
pkg-config --modversion gtk4 gstreamer-1.0 gstreamer-app-1.0 sqlcipher
gst-inspect-1.0 waylandsink
gst-inspect-1.0 pipewiresink
sqlcipher --version
flatpak-builder --version
```

## Flatpak prerequisites

Configure Flathub if it is not already available, then install the exact
runtimes used by the Phase 1 manifest:

```sh
flatpak remote-add --if-not-exists flathub \
  https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install flathub \
  org.gnome.Platform//50 \
  org.gnome.Sdk//50 \
  org.freedesktop.Sdk.Extension.rust-stable//25.08 \
  org.freedesktop.Platform.codecs-extra//25.08-extra
```

Use `--user` consistently on both commands if a per-user Flatpak installation
is preferred. Codec availability and licensing vary by runtime and jurisdiction;
the observed Phase 1 inventory is in
[codec-coverage.md](prototypes/flatpak-smoke/codec-coverage.md).

## Build and run the Phase 1 prototype application

Build and install the current smoke application from the repository root:

```sh
flatpak-builder --force-clean --user --install \
  .flatpak-build \
  prototypes/flatpak-smoke/io.github.osv_ng.Phase1.yml
```

The Phase 1 manifest temporarily accesses the network to resolve locked Rust
crates and download a checksum-pinned SQLCipher archive. Phase 2 will vendor the
Rust sources and remove build networking.

Run the automated sandbox integration test:

```sh
flatpak run io.github.osv_ng.Phase1 --self-test
```

A successful run reports `wayland=true`, helper supervision, SQLCipher 4.18,
GStreamer, audio, and `seekable_av=true`.

Run the interactive smoke application:

```sh
flatpak run io.github.osv_ng.Phase1
```

Confirm that the custom theme is visible, the file chooser opens through the
desktop portal, and the audio probe plays. The application intentionally has no
broad filesystem permission.

## Run the native prototypes

The GTK gallery can run directly with a bounded automatic scroll measurement:

```sh
cargo run --release \
  --manifest-path prototypes/gtk-gallery/Cargo.toml -- \
  --items 100000 \
  --css prototypes/gtk-gallery/sample.css \
  --auto-scroll-seconds 10
```

Generate the public synthetic A/V fixture and test application-fed seeking:

```sh
gst-launch-1.0 -e \
  oggmux name=mux ! filesink location=/tmp/osv-phase1.ogv \
  videotestsrc num-buffers=300 pattern=ball ! \
    video/x-raw,framerate=30/1,width=640,height=360 ! theoraenc ! queue ! mux. \
  audiotestsrc num-buffers=431 wave=sine ! \
    audioconvert ! vorbisenc ! queue ! mux.

cargo run --release \
  --manifest-path prototypes/gstreamer-seek/Cargo.toml -- \
  --input /tmp/osv-phase1.ogv --output fake --run-seconds 10
```

Use `--output real` for interactive Wayland/PipeWire playback. Compare the two
media-worker authority boundaries with:

```sh
cargo run --release \
  --manifest-path prototypes/media-boundary/Cargo.toml -- \
  --input /tmp/osv-phase1.ogv --mode object-key --exercise-restart
cargo run --release \
  --manifest-path prototypes/media-boundary/Cargo.toml -- \
  --input /tmp/osv-phase1.ogv --mode broker --exercise-restart
```

The SQLCipher crash/recovery and plaintext-canary experiment requires a new,
empty output directory for each run:

```sh
cargo run --release \
  --manifest-path prototypes/sqlcipher/Cargo.toml -- \
  --directory /tmp/osv-sqlcipher-manual-check
```

Each prototype has additional controls and interpretation notes in its own
README under [`prototypes/`](prototypes/README.md).

## Test all Phase 1 Rust prototypes

There is deliberately no root Cargo workspace yet. Run formatting, unit tests,
and warnings-as-errors against each isolated manifest:

```sh
for manifest in prototypes/*/Cargo.toml; do
  cargo fmt --manifest-path "$manifest" -- --check
  cargo test --manifest-path "$manifest"
  cargo clippy --manifest-path "$manifest" --all-targets -- -D warnings
done
```

Then build/install the Flatpak and run `--self-test` as shown above. Manual Phase
1 checks still include keyboard/focus/accessibility behavior, mixed-scale
outputs, portal cancellation, theming, and representative hardware/software
video playback.

## Security and contribution context

Read [AGENTS.md](AGENTS.md), [the threat model](docs/threat-model.md), and the
[architecture decisions](docs/adr/README.md) before changing security or storage
behavior. Prototype success does not weaken the rule that unauthenticated media,
archives, database contents, and sidecars are hostile input.
