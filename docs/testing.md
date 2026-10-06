# Testing

Automated tests cover logic that is tedious or unsafe to verify by hand. The
manual matrix covers what only exists on a real phone, a real network, and a
real release.

## Automated

Server (from `raemote_cli/`):

```sh
cargo test                    # unit tests + doctests
cargo clippy --all-targets    # lints
```

iOS (from `raemote_ios/Raemote Connector/`):

```sh
# Build
xcodebuild -project "Raemote Connector.xcodeproj" -scheme "Raemote Connector" \
  -destination 'generic/platform=iOS Simulator' build

# Tests (pick any available simulator)
xcodebuild -project "Raemote Connector.xcodeproj" -scheme "Raemote Connector" \
  -destination 'platform=iOS Simulator,name=iPhone 17' test
```

Automated coverage focuses on: token minting/expiry/lockout, revocation and
persistence, the rate/concurrency limiter, IPC framing, probe/title parsing and
discovery filtering, the error-body shape, log tailing, and the proxy's request
rewriting and error rendering.

## Manual matrix

Run this before a release, on a physical phone and a real server. Record the
result of each row; file anything that fails.

Legend: **ID** · Steps → *Expected*.

### A. Install and service

| ID | Steps | Expected |
| --- | --- | --- |
| A1 | On a clean machine (`HOME=$(mktemp -d)`), run the install one-liner. | Downloads the latest release, verifies the checksum, installs `raemote`/`raemoted`, creates a `0700` config, prints the pairing link + QR. |
| A2 | `raemote status` after install. | Reports the node id, paired/connected counts, discovery count. |
| A3 | `raemote doctor`. | All checks pass (exit 0), or warns with a clear next step. |
| A4 | `raemote service status`; log out and back in. | The service is installed and the daemon is running again after login. |
| A5 | Re-run the installer over an existing install. | It stops/replaces cleanly; the node id and paired devices are unchanged. |
| A6 | `install.sh --uninstall`; then `--uninstall --purge`. | Binaries and service removed; `--purge` also removes `~/.raemote`. |

### B. Pairing and trust

| ID | Steps | Expected |
| --- | --- | --- |
| B1 | `raemote pair` → scan with the app. | Apps appear. |
| B2 | Pair via **Manual Setup** (paste the link). | Succeeds. |
| B3 | Wait past the TTL, then try the old link. | Rejected; pair again to get a new link. |
| B4 | Pair a second device while the first keeps working. | Both devices work. |
| B5 | `raemote devices list`. | Shows every paired device. |

### C. Revocation

| ID | Steps | Expected |
| --- | --- | --- |
| C1 | `raemote devices revoke <node-id>`. | Succeeds; the device disappears from the list. |
| C2 | Use the revoked device. | It is refused immediately (the app shows a clear reason). |
| C3 | Restart the daemon (`raemote restart`) and retry the revoked device. | Still refused. |
| C4 | Re-pair the same device with a fresh `raemote pair`. | Access is restored. |

### D. Persistence and recovery

| ID | Steps | Expected |
| --- | --- | --- |
| D1 | `raemote restart`. | Devices stay paired; apps stay. |
| D2 | Reboot the machine. | The service starts; devices stay paired. |
| D3 | Lock/unlock the phone; background/foreground the app. | The connection recovers without re-pairing. |
| D4 | Switch Wi-Fi ↔ cellular. | The connection recovers. |
| D5 | Force-quit the app and reopen. | It reconnects; the last app's session data is intact. |
| D6 | Put the server to sleep, then wake it. | The app reconnects (possibly after the foreground refresh). |

### E. Network and relays

| ID | Steps | Expected |
| --- | --- | --- |
| E1 | Run the daemon with no outbound proxy on an open network. | A direct connection is established (relay only if needed). |
| E2 | Block iroh infrastructure, then use `raemote doctor`. | The relay check fails with a hint pointing at the outbound proxy. |
| E3 | Set `[network] proxy` (or `--proxy`) and restart; retry pairing. | Works through the proxy; `doctor` shows the proxy reachable and skips the direct relay probe. |
| E4 | Kill the network entirely, then use the app. | A clear reason appears (not a silent hang); it recovers when the network returns. |

### F. Discovery and apps

| ID | Steps | Expected |
| --- | --- | --- |
| F1 | Start a new local web app. | It appears within the rescan interval. |
| F2 | Tap refresh in the app. | New apps appear immediately. |
| F3 | Stop an app. | It disappears on the next scan. |
| F4 | Run a local HTTP proxy (e.g. xray). | It is **not** listed. |
| F5 | `raemote apps hide <name>` then `raemote apps unhide <host:port>`. | The app disappears and returns; `apps list` is correct immediately. |
| F6 | `raemote apps add myserver 8080` for an app discovery missed. | It appears as a manual entry and routes. |
| F7 | Open a heavy app (many assets) in the phone. | It renders and stays stable. |
| F8 | Open an app whose server is stopped. | A readable error page appears in the web view (not raw JSON). |

### G. Diagnostics

| ID | Steps | Expected |
| --- | --- | --- |
| G1 | `raemote logs -n 50`; `raemote logs --follow`. | Recent activity shows; follow streams (Ctrl-C exits cleanly). |
| G2 | `raemote doctor --json`. | Valid JSON with an `ok` boolean and a `checks` array. |
| G3 | Stop the daemon, then `raemote doctor`. | Fails (exit 1) with a "start it" hint. |
| G4 | `raemote status --json`. | Includes `active_connections`, `relay_urls`, `bound_sockets`. |

## Recorded results

| Date | Version | Tester | Failures |
| --- | --- | --- | --- |
| | | | |
