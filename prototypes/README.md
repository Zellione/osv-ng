# Phase 1 prototype prerequisites

These experiments are intentionally independent of the future Phase 2 Cargo
workspace. The commands below describe the current Arch Linux development host;
they are not yet the stable-release support policy.

## Arch Linux packages

Install the build toolchain and minimum native dependencies:

```sh
sudo pacman -S --needed \
  base-devel pkgconf rustup \
  gtk4 \
  gstreamer gst-plugins-base gst-plugins-bad gst-plugin-pipewire \
  sqlcipher \
  flatpak flatpak-builder
rustup default stable
```

The minimum set supports the synthetic Theora/Vorbis tests, `appsrc`, native
Wayland output, and PipeWire audio. Install the broader system codec set for
representative user-media and software/hardware decoder coverage:

```sh
sudo pacman -S --needed \
  gst-plugins-good gst-plugins-ugly gst-libav
```

Codec presence and legal availability vary by Flatpak runtime, extension, and
jurisdiction. Installing these packages is test coverage, not approval to bundle
every codec.

## Flatpak SDK and runtimes

The Phase 1 manifest targets GNOME 50, which currently uses the Freedesktop
25.08 SDK base. Install the matching SDK, runtime, Rust extension, and expanded
codec extension in the same installation (`--user` may replace the default
system installation if used consistently):

```sh
flatpak install flathub \
  org.gnome.Platform//50 \
  org.gnome.Sdk//50 \
  org.freedesktop.Sdk.Extension.rust-stable//25.08 \
  org.freedesktop.Platform.codecs-extra//25.08-extra
```

The codec extension is deliberately a runtime dependency rather than bundled
source. Its coverage and licenses must be recorded before the Phase 1 stack
decision.

## Host checks

```sh
rustc --version
pkg-config --modversion gtk4 gstreamer-1.0 gstreamer-app-1.0 sqlcipher
flatpak-builder --version
flatpak list --runtime
```

Run the experiments only on a native Wayland session for supported display
results. X11/XWayland results are incidental.
