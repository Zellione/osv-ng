# Architecture decision records

ADRs capture decisions that constrain implementation or security claims. The
roadmap remains the delivery source of truth; an ADR supplies the reasoning and
consequences behind a material choice.

Statuses are `Proposed`, `Accepted`, `Superseded`, or `Rejected`. A provisional
technology choice stays `Proposed` until its roadmap feasibility gate passes.
Superseding an ADR requires a new ADR that links back to the old one.
Start new decisions from [the ADR template](0000-template.md).

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-rust-primary-language.md) | Rust as the primary language | Accepted |
| [0002](0002-sqlcipher-catalog.md) | SQLCipher catalog | Accepted |
| [0003](0003-encrypted-object-store.md) | Independently encrypted object store | Accepted |
| [0004](0004-vault-concurrency.md) | Exclusive writer or shared readers | Accepted |
| [0005](0005-offline-backup.md) | Closed-vault directory copy | Accepted |
| [0006](0006-parser-isolation-goal.md) | Object-scoped parser isolation | Accepted |
| [0007](0007-gtk4-ui-stack.md) | GTK4 as the initial UI stack | Accepted |
| [0008](0008-gstreamer-media-stack.md) | GStreamer as the initial media stack | Accepted |
| [0009](0009-brokered-media-plaintext.md) | Brokered authenticated plaintext for media workers | Accepted |
