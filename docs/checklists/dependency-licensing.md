# Dependency and licensing review checklist

Apply this before adding or materially upgrading a Rust crate, native library,
GStreamer plugin/runtime extension, Flatpak module, bundled asset, or tool that
ships with or influences a release. The project itself is MIT licensed.

## Need and provenance

- [ ] The dependency solves a stated requirement and existing approved
  dependencies or standard-library facilities were considered.
- [ ] The canonical upstream, exact package/crate/module identity, version
  policy, and maintainer activity are recorded.
- [ ] Source and release artifacts use authenticated transport and a pinned
  checksum, commit, or lockfile as appropriate.
- [ ] Generated/vendored code and transitive native components are identified.

## License compatibility

- [ ] SPDX expressions for direct and transitive shipped components are
  collected from authoritative package metadata and license files.
- [ ] License texts, notices, attribution, source-offer, relinking, and
  modification-disclosure obligations are understood and included in packaging.
- [ ] Copyleft or source-available terms are reviewed for compatibility with MIT
  distribution and Flatpak bundling; ambiguous/custom terms block release
  pending maintainer or legal review.
- [ ] Optional features do not silently add incompatibly licensed code.
- [ ] Media codecs, patent constraints, and jurisdiction/runtime-extension
  variability are documented separately from copyright license compatibility.
- [ ] Test/dev tools not shipped are distinguished from runtime deliverables.

## Security and maintenance

- [ ] The dependency's input exposure, process authority, unsafe/FFI surface,
  build scripts, network behavior, and secret-memory implications are reviewed.
- [ ] Default features are disabled unless needed; enabled features are listed.
- [ ] Known vulnerabilities and unmaintained/yanked status are checked with the
  Phase 2 dependency-policy tooling once available.
- [ ] Update cadence, responsible owner, and replacement/removal path are named.
- [ ] A library limitation does not weaken a security invariant; affected
  behavior is gated or exposed as a documented degraded state.

## Reproducibility and targets

- [ ] The version is locked and a clean Arch build succeeds without undeclared
  host dependencies.
- [ ] The Flatpak manifest pins sources and required SDK/runtime extensions; no
  build-time network access is assumed during reproducible builds.
- [ ] Native ABI/version checks cover SQLCipher, GTK, GStreamer, codec/archive
  libraries, and helper sandbox facilities where relevant.
- [ ] Wayland runtime behavior and portal/device permissions are tested for
  dependencies that touch display, audio, GPU, files, or process launch.
- [ ] Removal of build caches does not remove required license/notice outputs.

## Release evidence

- [ ] The dependency inventory/SBOM and bundled notices are regenerated.
- [ ] Format, lint, test, advisory/license policy, and Flatpak verification gates
  pass using the documented Phase 2 commands.
- [ ] Any exception has an ADR or roadmap entry with scope, risk, expiry/review
  date, and user-visible limitation where applicable.
