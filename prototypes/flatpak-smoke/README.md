# Flatpak stack smoke prototype

This minimal GNOME 50 Flatpak exercises the first-release integration risks in
one sandboxed process:

- GTK4 theming on a Wayland-only display permission;
- an explicit desktop file chooser portal action;
- GStreamer registry discovery and a user-triggered audio probe through the
  Flatpak PulseAudio-compatible socket (normally backed by PipeWire on the host);
- application-supplied seekable video with audio and three random seeks using a
  generated public Theora/Vorbis fixture inside the sandbox;
- DRI exposure for hardware-decoder discovery;
- SQLCipher 4.18.0 built from a pinned upstream archive and opened with a raw
  key in memory-only temp mode; and
- supervised launch of the same installed binary in a narrow helper mode.

Install all packages and runtimes from the
[consolidated prototype prerequisites](../README.md).

## Build, install, and run

From the repository root:

```sh
flatpak-builder --force-clean --user --install \
  .flatpak-build \
  prototypes/flatpak-smoke/io.github.osv_ng.Phase1.yml
flatpak run io.github.osv_ng.Phase1 --self-test
flatpak run io.github.osv_ng.Phase1
```

The self-test requires Wayland, checks helper/SQLCipher/GStreamer integration,
runs a bounded sandbox-audio pipeline to EOS, and plays/seeks the packaged
synthetic A/V fixture through `GstAppSrc`. In the interactive app,
confirm the portal opens without broad filesystem permission, the audio button
produces a quiet tone, and the theme is applied. Test hardware decoder use with
a representative supported video; the displayed candidate count proves registry
availability only, not successful hardware playback.

The observed decoder families, hardware candidates, plugin licenses, and
runtime-license caveats are recorded in [codec-coverage.md](codec-coverage.md).
Regenerate that inventory whenever the runtime, codec extension, or manifest
changes.

The Phase 1 manifest temporarily permits network access while Cargo resolves its
locked crates. Phase 2 must replace this with generated, checksummed Cargo
sources and remove build networking before this can be a reproducible or
release-quality manifest.
