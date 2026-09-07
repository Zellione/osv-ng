# GStreamer seekable-source feasibility prototype

This Phase 1 experiment supplies encoded bytes through a random-access
`GstAppSrc`; GStreamer never opens the input path. It decodes video and audio,
performs three random seeks, bounds encoded and decoded queues, reports selected
decoders, measures seek completion, and cancels after a fixed deadline.

`--output fake` is the deterministic automation mode. It decodes both streams
into synchronized fake sinks. `--output real` uses `waylandsink` for video and
`pipewiresink` for audio on the supported native-Wayland host path. The Flatpak
manifest uses `--output flatpak`, which sends audio through its
PulseAudio-compatible sandbox socket.

Install the exact Arch packages listed in the
[consolidated prototype prerequisites](../README.md). The broader GStreamer
codec packages are required for representative media beyond this synthetic
Theora/Vorbis fixture.

## Create a public synthetic fixture

The command below creates approximately ten seconds of generated audio/video;
it contains no private media:

```sh
gst-launch-1.0 -e \
  oggmux name=mux ! filesink location=/tmp/osv-phase1.ogv \
  videotestsrc num-buffers=300 pattern=ball ! \
    video/x-raw,framerate=30/1,width=640,height=360 ! theoraenc ! queue ! mux. \
  audiotestsrc num-buffers=431 wave=sine ! audioconvert ! vorbisenc ! queue ! mux.
```

## Build and run

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo run --release -- --input /tmp/osv-phase1.ogv --output fake --run-seconds 10
cargo run --release -- --input /tmp/osv-phase1.ogv --output real --run-seconds 10
```

The prototype bounds the appsrc queue at 2 MiB, individual source reads at 256
KiB, video at three decoded buffers, and audio at sixteen decoded buffers. Its
byte counter measures decoded buffers crossing the branch, not every internal
decoder/driver allocation. Hardware decode is observed through selected-element
logging; forced-software and representative large-video coverage remain required
before the GStreamer Phase 1 decision.
