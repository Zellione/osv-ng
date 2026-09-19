# ADR 0012: Isolated desktop-portal broker process

- Status: Accepted
- Date: 2026-09-19
- Owners: project maintainers
- Roadmap links: Security architecture; Phase 8; Phase 9
- Supersedes: none

## Context

The application clears Linux process dumpability before GTK starts handling
secrets. `xdg-desktop-portal` authenticates a native caller by inspecting its
process root through `/proc/<pid>/root`; Linux denies that inspection for the
non-dumpable application. The result is a dead file/folder chooser even though
the portal and its GTK backend are healthy.

Temporarily restoring dumpability around a chooser is unsafe once a vault is
open: another same-user process could race the window and inspect keys or
plaintext. Permanently retaining dumpability would contradict the recorded
process-hardening boundary. Direct path-based GTK choosers would discard the
approved portal authority boundary.

## Decision

Run portal selection in a short-lived mode of the application executable that
does not open a vault, receive credentials, or apply the secret-bearing process
hardening profile. The hardened application gives the broker only one inherited
local IPC endpoint and a fixed chooser purpose. The broker invokes GTK's portal
file dialog, opens the selected object immediately with no-follow/type checks,
and returns its display path plus the stable descriptor using `SCM_RIGHTS`.

The hardened application accepts exactly one bounded response, rejects missing
or extra descriptors and malformed paths, reaps the broker, and retains the
descriptor as the selected authority. Cancellation and failure return no
descriptor. Lock or replacement revokes retained authority.

The broker must never receive a vault path, vault descriptor, password, key,
catalog value, decrypted name, media bytes, or unrestricted application IPC.

## Consequences

- The main process remains non-dumpable for its complete secret-bearing
  lifetime while portal caller authentication remains functional.
- A compromised portal/broker can influence only one user-selected object; all
  returned data remains untrusted and is independently checked by the hardened
  application.
- Native selection adds a short-lived process and descriptor-passing protocol.
- The broker itself is dumpable and therefore must remain permanently outside
  every secret-bearing code path.
- The visible portal dialog is not transient-parented to the hardened window in
  the initial implementation. Modality is enforced by disabling overlapping
  chooser requests in application state; compositor grouping can be added
  later without expanding broker authority.

## Alternatives considered

- Leaving the main process dumpable was rejected because it weakens the
  established ptrace boundary for keys and decoded plaintext.
- Toggling dumpability around requests was rejected because the race is not
  safely bounded after unlock.
- A direct non-portal chooser was rejected because it abandons the approved
  desktop authority boundary and does not address Flatpak integration.
- A permanently running UI broker was rejected because it retains unnecessary
  ambient authority and complicates lock-time revocation.

## Validation and reversal

Tests must cover one-response framing, missing/extra/wrong-type descriptors,
oversized and malformed paths, cancellation, broker crash, and replacement
revocation. Native Wayland and packaged Flatpak checks must demonstrate folder
selection, cancellation, image selection, and broker reaping while the main
process remains non-dumpable. If the portal gains a caller-authentication path
compatible with non-dumpable processes, remove the broker after proving that
behavior on supported native and Flatpak environments.
