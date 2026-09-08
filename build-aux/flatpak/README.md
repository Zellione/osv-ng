# Phase 2 Flatpak workspace bootstrap

This manifest verifies the production Cargo workspace and helper layout inside
the accepted GNOME SDK. `io.github.osv_ng.Phase2` is a temporary bootstrap ID,
not the release application ID. It installs no desktop metadata and grants no
runtime permissions. Select and record the product ID before adding release
metadata or treating the manifest as distributable packaging.

`cargo-sources.json` contains checksum-pinned crates generated from the root
lockfile. Flatpak Builder downloads and verifies those sources before entering
the build sandbox; both test and release builds then set Cargo offline mode, so
any undeclared source fails the build instead of accessing the network.

Regenerate the file after a root dependency change with commit
`1fc32195e3e60fe5c97f0af646dec7a99df5962b` of Flatpak's
`flatpak-builder-tools`:

```sh
python3 flatpak-builder-tools/cargo/flatpak-cargo-generator.py \
  Cargo.lock \
  -o build-aux/flatpak/cargo-sources.json
```

Review every URL and checksum change before committing it.

From the repository root, with the runtimes listed in the main README installed:

```sh
flatpak-builder --force-clean --disable-rofiles-fuse \
  .flatpak-phase2 \
  build-aux/flatpak/io.github.osv_ng.Phase2.yml
```

The manifest builds all production workspace members, runs all tests in release
mode, and installs the application plus both helper binaries. Because the
application entry point is only a Phase 2 stub, successful execution proves SDK
and packaging mechanics only; it does not prove GTK, media, portal, or release
sandbox behavior.
