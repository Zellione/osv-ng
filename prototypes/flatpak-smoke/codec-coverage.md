# Flatpak codec and license inventory

Recorded 2026-09-07 from the installed `org.gnome.Platform//50` runtime and
its `org.freedesktop.Platform.codecs-extra//25.08-extra` extension on x86-64.
This is Phase 1 feasibility evidence, not a permanent codec guarantee or legal
advice. Runtime updates can change both features and their licensing; release
builds must regenerate and review this inventory.

## Observed coverage

`gst-inspect-1.0 --types=Decoder/Video` reported 226 plugins and 1,527 total
features. Relevant video decoder families included:

- FFmpeg/libav software decoders for H.264/AVC, H.265/HEVC, H.266/VVC,
  MPEG-1/2/4, VP8, VP9, AV1, and many legacy formats;
- native AV1 decoding through AOM and dav1d;
- native Theora and VP8/VP9 decoding;
- VA-API candidates `vaav1dec`, `vah264dec`, `vah265dec`, `vavp9dec`, and
  `vavp9alphadecodebin`; and
- Vulkan H.264 and H.265 decoder candidates.

The packaged synthetic Theora/Vorbis Ogg fixture completed three random seeks,
decoded video and audio, and reached EOS through the Wayland and sandbox-audio
path. Hardware entries prove registry availability only. Representative files
must still demonstrate that hardware negotiation succeeds and that software
fallback works on supported hardware.

## Plugin metadata

The following values come from `gst-inspect-1.0` inside the installed Flatpak:

| Plugin | Source module | Reported plugin license |
|---|---|---|
| `libav` | `gst-libav` | LGPL |
| `va`, `vulkan`, `aom` | `gst-plugins-bad` | LGPL |
| `dav1d` | `gst-plugin-dav1d` | MIT/X11 |
| `theora`, `ogg`, `vorbis`, `app` | `gst-plugins-base` | LGPL |
| `vpx`, `pulseaudio` | `gst-plugins-good` | LGPL |

All GStreamer plugins above reported version 1.26.11 except the Rust dav1d
plugin, which reported 0.15.3-6302bea. The runtime also ships license notices
for AOM, dav1d, FFmpeg, libogg, libtheora, libva, libvorbis, libvpx, PipeWire,
and PulseAudio. FFmpeg's installed notice says its normal combined license is
LGPL-2.1-or-later, but optional GPL components and linked external libraries
can change that result. The final distribution review must inspect the exact
runtime commit and FFmpeg configuration, retain required notices, and account
for patent or jurisdictional restrictions separately from copyright licenses.

## Recheck commands

Run these inside the installed application after every runtime or manifest
change:

```sh
flatpak run --command=gst-inspect-1.0 \
  io.github.osv_ng.Phase1 --types=Decoder/Video
flatpak run --command=gst-inspect-1.0 io.github.osv_ng.Phase1 libav
flatpak run --command=gst-inspect-1.0 io.github.osv_ng.Phase1 va
flatpak run --command=gst-inspect-1.0 io.github.osv_ng.Phase1 dav1d
```

Also inspect the matching runtime's `files/share/licenses` tree; plugin metadata
does not replace review of linked codec-library and runtime-extension licenses.
