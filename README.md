<p align="center">
  <img src="https://github.com/raemote/raemote_cli/raw/main/Raemote_ICON.png" width="112" alt="Raemote icon">
</p>

# Raemote

Use the web apps running on your computer — from your phone, laptop, anywhere.

`raemoted` is a small server daemon you run on your own machine. It finds the web apps
already running there (Jellyfin, Home Assistant, a dev server — anything on
`http://localhost`) and makes them reachable from two clients that ship with it:
the **Raemote iOS app** and **`raemote connect`**, a browser client that serves
the same apps from any computer. No account, no VPN, no port forwarding: the
connection is end-to-end encrypted and goes direct when it can, otherwise
through a public relay.

Think of this as an encrypted, p2p connected and super easy to setup reverse proxy.

<a href="https://testflight.apple.com/join/3AQeWyUR"><img src="https://github.com/raemote/raemote_cli/raw/main/testflight_badge.svg" alt="Available on TestFlight" height="64"></a>

## Install

macOS (Apple Silicon, Intel) or Linux (x86_64, arm64 — a Raspberry Pi works):

```sh
curl -fsSL https://github.com/raemote/raemote_cli/raw/main/install.sh | sh
```

On networks where GitHub is slow or unreliable, use the Gitee mirror (the
installer then prefers the Gitee release):

```sh
curl -fsSL https://gitee.com/pppkin/raemote_cli/raw/main/install.sh | sh
```

It installs `raemote` and `raemoted` into `~/.local/bin` and starts a background service.
Prefer to read it first? Download `install.sh`, then `sh install.sh`. Flags
include `--no-service`, `--bin-dir <dir>` and `--proxy <url>`.
Re-running it upgrades in place: the daemon restarts (live connections drop
briefly) with the same identity and paired devices, and the installer exits
non-zero — with recovery hints — if the service fails to come up.

## Pair

```sh
raemote pair                     # pairing link granting every app (QR code too)
raemote pair --ports 3000,8080   # restricted link: only these apps
```

Open the Raemote app, tap **+**, scan the QR code (or paste the link via
**Manual Setup**). The same link pairs a computer instead — or as well (see
[Connect](#connect)). You only do this once per device. Already paired? Any
paired device can introduce another: **server → … → Invite Device…** shows a
one-time code.

## Connect

`raemote connect` is Raemote's browser client — your apps in a desktop
browser, over the same encrypted tunnel as the phone app:

```sh
raemote connect '<link from raemote pair>'   # pair this machine, open the web UI
raemote connect                              # reopen the last server
```

It serves the app list at `http://127.0.0.1:7788` (`--port <n>` moves it,
`--no-open` skips the browser), and every app then opens on **its own**
`127.0.0.1` port (7790+) — so relative URLs, cookies and logins behave exactly
as they do on the server. Requests stream end to end: bodies, server-sent
events and WebSockets pass through untouched. It runs on the server machine or
any other computer.

The paired computer shows up in `raemote devices list` like any phone — give it
a name, restrict it with `--ports`, revoke it when you're done.

## Commands

```sh
raemote status                        # running? how many apps found?
raemote discover                      # rescan now (also runs every 30s)
raemote connect [<uri|node-id>]       # browse this server's apps in a local web UI
raemote apps list                     # what was found, plus manual entries
raemote apps add <name> <port>        # pin an app discovery missed
raemote apps hide <name|host:port>    # hide a false positive (unhide restores it)
raemote devices list                  # paired devices (with each one's access)
raemote devices rename <node-id> "Leo's iPhone"
raemote devices revoke <node-id>      # cut a device off
raemote devices access <node-id> --ports 3000,8080   # restrict to these apps
raemote devices access <node-id> --all               # restore full access
raemote config set name "Living Room Mac mini"
raemote doctor                        # health check — start here when something's off
raemote logs -n 50                    # recent activity (--follow to stream)
raemote stop | start | restart
```

## Notes

- **Discovery** is automatic and temporary; `raemote apps add` entries are
  permanent. An app must answer `GET /` like a web page — `raemote discover
  --verbose` lists every listener that was skipped and why.
- **Per-device access**: by default a paired device reaches every app. Mint a
  restricted pairing link with `raemote pair --ports 3000,8080`, or narrow an
  already-paired device with `raemote devices access <node-id> --ports …`
  (`--all` restores full access). Restricted devices only *see* the apps in
  their allowlist, and any attempt to open another returns `403`. A paired
  device's **Invite Device…** link can only ever grant a subset of what that
  device already has — it can never widen access, so sharing on to a friend
  stays within your original grant. To make restriction the default for every
  link this server mints, set `bind.allow_ports = [3000, 8080]` in config
  (`raemote config set bind.allow_ports 3000,8080` works too); a per-link
  `raemote pair --ports`/`--all` overrides it, and setting it alongside a
  pinned `token` keeps that link's restriction across restarts.
- **Long-lived pairing link**: pin a token in `~/.raemote/config.toml`
  (`[bind]` → `token = "…64 hex…"`, `token_ttl_secs = 3153600000`) or set
  `RAEMOTE_BIND_TOKEN`, then `raemote pair`. That link is a secret — anyone
  holding it can pair. Use `raemote pair --ttl <secs>` to mint a long-lived
  link without editing config.
- **Uninstall**: re-run the installer with `--uninstall` (add `--purge` to also
  delete `~/.raemote`, including this server's identity).

## Documentation

[How it works](https://github.com/raemote/raemote_cli/blob/main/docs/how-it-works.md) · [Troubleshooting](https://github.com/raemote/raemote_cli/blob/main/docs/troubleshooting.md) ·
[Threat model](https://github.com/raemote/raemote_cli/blob/main/docs/threat-model.md) · [Security](https://github.com/raemote/raemote_cli/blob/main/SECURITY.md) ·
[Privacy](https://github.com/raemote/raemote_cli/blob/main/PRIVACY.md) · [Acceptable use](https://github.com/raemote/raemote_cli/blob/main/docs/acceptable-use.md) ·
[AI-agent install](https://github.com/raemote/raemote_cli/blob/main/docs/agent-install.md) · [Releasing](https://github.com/raemote/raemote_cli/blob/main/RELEASING.md)

GitHub: <https://github.com/raemote/raemote_cli> — Gitee mirror:
<https://gitee.com/pppkin/raemote_cli>

iOS app: <https://github.com/raemote/raemote_connector_ios> — Gitee mirror:
<https://gitee.com/pppkin/raemote_connector_ios>

Browser client (`raemote connect`): see [Connect](#connect) above — it lives in
this repo and crate.

## License

AGPL-3.0-or-later — see [LICENSE](https://github.com/raemote/raemote_cli/blob/main/LICENSE).
