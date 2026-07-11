# SSP / Bootstrap / App Finalization Plan

Last updated: 2026-07-11

This plan covers the SSP workspace at `/home/thomas/Coding/SLPauth` and the standalone chat app at `/home/thomas/Coding/ssp_app`.

## Current confirmed manual test context

Recently tested manually:

- Two PCs.
- One Windows, one Hyprland/Linux.
- Same Wi-Fi.
- Peers connected over DHT and the live server path.

Important correction: the recurring Hyprland/Linux issue is an intermittent compositor “Application Not Responding” notification, **not an actual app freeze**. It is not specific to webcam use; webcam can function normally. Windows currently behaves acceptably for this issue.

## Immediate code changes already made or intended

### `ssp-client`

1. **Do not block setup on DHT scans**
   - `setup_discovery` should subscribe to gossip and start accepting handshakes immediately after the bootstrap attempt.
   - DHT publish/scan must run in the background.
   - Motivation: clients should not sit in `Discovering` for 20–30 seconds while initial DHT scans complete.

2. **Remove verbose handshake timing logs**
   - Removed app-side temporary connect/join logs.
   - Removed detailed SSP handshake timing logs.
   - Keep only actionable errors/rejections.

3. **Handshake encryption policy fields**
   - Add/keep explicit handshake fields:
     - `encryption_enabled`
     - `accept_encrypted`
     - `accept_unencrypted`
   - Default behavior should remain encrypted-only.
   - `SessionBuilder::set_encryption(false)` should switch to unencrypted-only for tests/debug use.
   - `SessionBuilder::set_encryption_acceptance(...)` allows explicit policy configuration.

### `ssp_bootstrap`

No major immediate cleanup identified beyond test/deployment hardening. Keep current health/stats/TTL/full endpoint address behavior.

### `ssp_app`

1. **Remove extra test binaries**
   - Remove:
     - `src/bin/tight.rs`
     - `src/bin/wide.rs`
     - `src/bin/mismatch.rs`
   - Remove Cargo `[[bin]]` entries and obsolete profile features.
   - Simplify `connect.rs` to use normal `SessionBuilder` defaults.

2. **Webcam defaults**
   - Default webcam FPS is now `30.0` for new/missing config values.
   - Existing user config files will keep their saved value unless migrated/reset.

3. **Webcam performance**
   - Decode remote webcam JPEG frames off the UI thread.
   - Cache decoded `egui::ColorImage` for app GUI upload.
   - Cache 200x112 BGRA for native Windows overlay.
   - This may still help general performance, but the primary remaining ANR issue to investigate is Hyprland/Linux.

4. **Avatar talking outline**
   - All avatars should be square.
   - Talking indicator should be visible as:
     - colored outer ring using profile/name/avatar color
     - dark inner gap/shadow for contrast
   - Webcam popup outlines are separate and should not be changed unless specifically requested.

5. **Mic threshold UI**
   - Remove the textual `input x.xxx` label from the mic threshold option.
   - Keep the visual input-level marker line.

## Important things still needing investigation or change

## 1. Hyprland “Application Not Responding” notification investigation

This is currently the highest-priority app polish/stability issue.

Known: Windows is fine here; the issue is Hyprland/Linux. The app does not necessarily freeze; Hyprland sometimes reports it as not responding even while the session/webcam/chat continue functioning.

Potential sources to audit and tune:

1. **UI-thread subprocess calls**
   - Audit every `hyprctl`, `xdotool`, shell command, or external command path.
   - Existing timeout wrappers help, but repeated spawning can still stall/compositor-thrash.
   - Confirm no blocking command is run directly on the egui update/render thread.
   - Prefer cached/background compositor state with throttled refresh.

2. **Hyprland overlay hint application**
   - Ensure `apply_compositor_overlay_hints` cannot spawn repeatedly every frame.
   - Ensure hint passes are bounded and only run when overlay geometry actually changes.
   - Consider one worker/channel for Hyprland commands rather than spawning many short-lived threads.

3. **Window/overlay positioning discovery**
   - `find_dolphin_rect_hyprctl` / `find_dolphin_rect_xdotool` should be throttled.
   - Do not query every frame.
   - Proposed cache interval:
     - game/window active: 250–500ms
     - no overlay visible: disabled or >=1s

4. **Webcam frame decode/upload**
   - Remote JPEG decode should be off UI thread.
   - Texture upload still happens on UI thread; cap uploads per frame.
   - Webcam is not currently believed to be the direct cause of the Hyprland notification, but still test under webcam load because it increases frame work:
     - no webcam
     - webcam 30fps
     - webcam 15fps
     - webcam 6fps
     - webcam receive-only
     - webcam send-only

5. **Repaint cadence**
   - Permanent session heartbeat repainting has been removed.
   - Background workers now request repaint when they have new information to show:
     - connect worker publishes a session
     - background network I/O receives messages/voice/video/session-end
     - webcam worker produces a new frame
     - update checker changes state/progress
   - The only delayed repaint left is a short voice-activity repaint while someone is talking, so the speaking border can clear after its timeout.
   - Needs Hyprland review: confirm event-driven repainting does not leave stale UI and reduces compositor “not responding” notifications.

6. **Audio backend/device enumeration**
   - JACK/ALSA probing emits noise and may block in some environments.
   - Ensure device enumeration is cached and not repeated every frame in options UI.
   - Consider async/manual refresh button for audio/webcam devices.
   - This is a likely candidate for brief UI-thread stalls that might trigger Hyprland's notification without permanently freezing the app.

7. **Native stderr suppression**
   - ALSA/JACK stderr suppression exists in voice code, but the startup logs show backend messages still happen.
   - Investigate whether some device queries happen outside suppression.

8. **Wayland/XWayland specifics**
   - Determine whether app runs native Wayland or XWayland under Hyprland.
   - Test `WINIT_UNIX_BACKEND=x11` vs Wayland if needed, but do not make wrapper scripts part of the normal test path.

## 2. Encryption/security review

The current encryption design needs a serious final review before calling it secure.

Questions / concerns:

1. **Default encryption parameters**
   - Current defaults:
     - rollover: `60,120,240`
     - offset: `30,60,120`
   - Need to confirm these are safe and practical for real Slippi rollback timing.
   - Need to decide whether negotiation should allow wide ranges in release, or exact/default-only.

2. **Key availability semantics**
   - Implemented intended behavior:
     - game seed should produce an initial key at game start, but this crosses async tasks/channels, so app data remains queued during the tiny race before `GameNet` receives the first key
     - first key emitted by the crypter becomes the active current key
     - if decryption fails, the message is dropped; ciphertext is not treated as plaintext
     - if encryption is disabled by the locked handshake mode, app data remains plaintext
   - Still needs targeted tests for initial-key race, decrypt-failure, and unencrypted mode behavior.

3. **Mixed encrypted/unencrypted sessions**
   - Implemented policy: if a client accepts both encrypted and unencrypted peers, the first peer locks the session mode. Future peers must match that locked mode.
   - `set_encryption(true)` is the strict encrypted-only selector; `set_encryption(false)` is the strict unencrypted-only selector.
   - Custom acceptance ranges default to offering encrypted app data whenever encrypted peers are allowed.
   - `ssp_app` relies on SSP defaults and uses encrypted-only mode, so it does not need an explicit `.set_encryption(true)` call.
   - Keep session-wide locking unless app-data encryption becomes per-peer/per-message.

4. **Handshake authenticity**
   - The handshake negotiates parameters over the Iroh connection.
   - Need to document what identity/authentication guarantees are provided by Iroh endpoint IDs and the signed gossip messages.

5. **Replay / downgrade risk**
   - Review whether a peer can force weaker encryption params or unencrypted mode.
   - Ensure handshake policy prevents downgrade when release defaults require encrypted.

6. **SSP version bump**
   - Adding encryption fields is JSON-compatible, but semantically important.
   - Decide whether to bump `SSP_VERSION` from `[0,1,0]` to `[0,1,1]` or similar.

7. **Threat model document**
   - Write a short document stating what encryption protects and does not protect.
   - Especially clarify this is gameplay-input-derived app-message encryption, not necessarily a full audited secure messaging protocol.

## 3. Discovery / DHT / bootstrap behavior to test

Must test these combinations:

1. Bootstrap up, zero peers.
   - First client should subscribe/accept immediately.
   - No long `Discovering` delay.

2. Bootstrap up, second peer arrives.
   - Peer should be found quickly through bootstrap.
   - Full endpoint addresses should be used.

3. Bootstrap down.
   - Client still subscribes immediately.
   - DHT publish/scan runs in background.
   - Later peer can connect through DHT.

4. Bootstrap slow.
   - Decide whether bootstrap should still be allowed to block for HTTP timeout or should also become fully background after an initial short attempt.

5. Relay down / custom relay fails.
   - Failed bootstrap/relay candidate should not permanently block future DHT candidate.

6. Same-Wi-Fi / LAN direct path.
   - Confirm full endpoint addr reduces connection delay.

7. Different NAT environments.
   - Need tests beyond same-Wi-Fi.

## 4. Session lifetime behavior to regression-test

Important rules:

1. First Dolphin `NewGame` creates session for seed A.
2. `GameEnd` before handshake should not end discovery for seed A.
3. Different local `NewGame` before SSP handshake should end old session and create a fresh one.
4. Different local `NewGame` after SSP handshake should preserve session and reannounce/exchange new seed.
5. Peer mismatching `NewGame` should end session.
6. Old-seed bootstrap/DHT follow-up should be cancelled where possible after session cancellation.

Need automated tests for all of these, not only manual app tests.

## 5. App-level `UserInfo` / join behavior to regression-test

Rules:

1. App should only leave `connecting...` after peer `UserInfo` is received.
2. App must not mark joined just because SSP reaches `Discovered`.
3. App should send `UserInfo` first after SSP `Discovered`.
4. Non-UserInfo app payloads should buffer until local `UserInfo` has been sent.
5. Do not fix ordering by periodic `UserInfo` resend.

Need tests or at least repeatable manual checklist.

## 6. Bootstrap server hardening and tests

Need tests for:

1. valid peer registration
2. second peer receives first peer
3. full endpoint address roundtrip
4. legacy peer ID fallback
5. invalid game hash rejected
6. invalid peer ID rejected
7. invalid endpoint addr rejected
8. TTL eviction
9. max games limit
10. `session=` validation/persistence
11. peer moving between games removes old-game entry

Deployment docs still needed:

- systemd service example
- ports/firewall
- health/stats monitoring
- log rotation

## 7. Release checklist

### SSP client

- `cargo fmt -p ssp-client`
- `cargo check -p ssp-client`
- `cargo test -p ssp-client`
- `cargo test -p ssp-client --test dolphin_mock -- --test-threads=1`
- Add handshake encryption tests
- Add non-blocking discovery/DHT tests
- Decide SSP version bump
- Commit/push

### Bootstrap

- `cargo check -p ssp-bootstrap`
- add bootstrap tests listed above
- test live `/health` and `/stats`

### Standalone app

- update `Cargo.lock` to pushed SSP client commit
- `cargo check`
- `cargo build --release`
- Windows smoke test
- Hyprland smoke test, watching specifically for compositor “not responding” notifications and correlating them with logs/actions
- 10–15 minute chat/voice/webcam soak test on Hyprland
- same-Wi-Fi two-PC test
- bootstrap path test
- DHT-only/fallback test
- close button / Ctrl-C behavior
- startup/autoupdate behavior

## 8. Known non-blocking cleanup

1. Existing warning in app:
   - `src/main.rs`: `let mut viewport` can be non-mut on some cfgs.
2. Review all `println!` / `eprintln!` / `debug_println!` before release.
3. Decide whether existing user configs with webcam FPS 6/15 should be migrated to 30 or left untouched. Current code only changes defaults for new/missing values.
4. Consider caching native Windows avatar BGRA too, although current ANR issue is Hyprland, not Windows.
