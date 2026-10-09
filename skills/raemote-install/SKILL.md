---
name: raemote-install
description: Set up the Raemote server on this machine so the user can reach local web apps from their phone. Use when the user asks to install/set up Raemote, expose local apps (Jellyfin, Home Assistant, a dev server, …) to their phone, or needs a raemote:// pairing link.
---

# Raemote server install

Raemote is a self-hosted server that lets a phone reach web apps running on this
machine. Installation is non-interactive and machine-verifiable.

Requires Raemote **0.2.0+** (for `pair`/`doctor`); on 0.1.x use `qr`/`status`.

## Steps

### 1. Install

```sh
curl -fsSL https://github.com/raemote/raemote_cli/raw/main/install.sh | sh -s -- --json
```

stdout is one JSON object:

```json
{"installed":true,"version":"0.2.0","bin_dir":"/home/you/.local/bin","service":true,"node_id":"<hex>","uri":"raemote://bind?..."}
```

- If `"service": false`, install it: `"<bin_dir>/raemote" service install`.
- Call the binary by its absolute `bin_dir` path (it may not be on `PATH`).
- Re-running is safe: it upgrades in place and preserves identity and paired
  devices.

### 2. Verify

```sh
"<bin_dir>/raemote" doctor --json
```

Healthy is exit `0` with `"ok": true`. On exit `1`, follow each check's `hint`.

### 3. Give the user a pairing link

```sh
"<bin_dir>/raemote" pair --json
```

```json
{"uri":"raemote://bind?node=<hex>&token=<hex>&exp=<unix>","expires_at_unix":1789379492}
```

Show the `uri` to the user (or run `"<bin_dir>/raemote" pair` in a terminal for a
QR code). Then tell them: install the **Raemote** iOS app, tap **+**, and scan
the code or paste the link.

## Rules

- The pairing `token` is a credential: show it only to the user who asked, never
  to shared logs.
- The link is short-lived; mint a fresh one with `pair` if the user is slow.
- On a restrictive network where `doctor` cannot reach the relay, configure an
  outbound proxy: `"<bin_dir>/raemote" config set network.proxy http://host:port`
  then `"<bin_dir>/raemote" restart`.
- Do not run the daemon as root.

Full reference: <https://github.com/raemote/raemote_cli>
