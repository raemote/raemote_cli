<p align="center">
  <img src="https://github.com/raemote/raemote_server/raw/main/Raemote_ICON.png" width="112" alt="Raemote icon">
</p>

# Raemote

Use the web apps running on your computer — from your phone, anywhere.

Raemote is a small server you run on your own machine. It finds the web apps
already running there (Jellyfin, Home Assistant, a dev server — anything on
`http://localhost`) and makes them reachable from the Raemote iOS app. No
account, no VPN, no port forwarding: the connection is end-to-end encrypted and
goes direct when it can, otherwise through a public relay that forwards it
without being able to read it.

<a href="https://testflight.apple.com/join/3AQeWyUR"><img src="https://github.com/raemote/raemote_server/raw/main/testflight_badge.svg" alt="Available on TestFlight" height="64"></a>

## Install

macOS (Apple Silicon, Intel) or Linux (x86_64, arm64 — a Raspberry Pi works):

```sh
curl -fsSL https://github.com/raemote/raemote_server/raw/main/install.sh | sh
```

On networks where GitHub is slow or unreliable, use the Gitee mirror (the
installer then prefers the Gitee release):

```sh
curl -fsSL https://gitee.com/pppkin/raemote_server/raw/main/install.sh | sh
```

It installs `raemote` into `~/.local/bin` and starts a background service.
Prefer to read it first? Download `install.sh`, then `sh install.sh`. Flags
include `--no-service`, `--bin-dir <dir>` and `--proxy <url>`.

## Pair

```sh
raemote pair                     # prints a raemote:// link and a QR code
```

Open the Raemote app, tap **+**, scan the QR code (or paste the link via
**Manual Setup**). You only do this once. Already paired? Any paired device can
introduce another: **server → … → Invite Device…** shows a one-time code.

No phone handy? The CLI can browse the same catalog itself:

```sh
raemote connect '<link from raemote pair>'   # pairs this machine, opens a local web UI
raemote connect                              # reopens the last one
```

It serves `http://127.0.0.1:7788` — apps listed with icons, proxied over the
same encrypted tunnel. `--port <n>` moves it, `--no-open` skips the browser.

## Commands

```sh
raemote status                        # running? how many apps found?
raemote discover                      # rescan now (also runs every 30s)
raemote connect [<uri|node-id>]       # browse this server's apps in a local web UI
raemote apps list                     # what was found, plus manual entries
raemote apps add <name> <port>        # pin an app discovery missed
raemote apps hide <name|host:port>    # hide a false positive (unhide restores it)
raemote devices list                  # paired devices
raemote devices rename <node-id> "Leo's iPhone"
raemote devices revoke <node-id>      # cut a device off
raemote config set name "Living Room Mac mini"
raemote doctor                        # health check — start here when something's off
raemote logs -n 50                    # recent activity (--follow to stream)
raemote stop | start | restart
```

## Notes

- **Discovery** is automatic and temporary; `raemote apps add` entries are
  permanent. An app must answer `GET /` like a web page — `raemote discover
  --verbose` lists every listener that was skipped and why.
- **Long-lived pairing link**: pin a token in `~/.raemote/config.toml`
  (`[bind]` → `token = "…64 hex…"`, `token_ttl_secs = 3153600000`) or set
  `RAEMOTE_BIND_TOKEN`, then `raemote pair`. That link is a secret — anyone
  holding it can pair. Use `raemote pair --ttl <secs>` to mint a long-lived
  link without editing config.
- **Uninstall**: re-run the installer with `--uninstall` (add `--purge` to also
  delete `~/.raemote`, including this server's identity).

## Documentation

[How it works](https://github.com/raemote/raemote_server/blob/main/docs/how-it-works.md) · [Troubleshooting](https://github.com/raemote/raemote_server/blob/main/docs/troubleshooting.md) ·
[Threat model](https://github.com/raemote/raemote_server/blob/main/docs/threat-model.md) · [Security](https://github.com/raemote/raemote_server/blob/main/SECURITY.md) ·
[Privacy](https://github.com/raemote/raemote_server/blob/main/PRIVACY.md) · [Acceptable use](https://github.com/raemote/raemote_server/blob/main/docs/acceptable-use.md) ·
[AI-agent install](https://github.com/raemote/raemote_server/blob/main/docs/agent-install.md) · [Releasing](https://github.com/raemote/raemote_server/blob/main/RELEASING.md)

GitHub: <https://github.com/raemote/raemote_server> — Gitee mirror:
<https://gitee.com/pppkin/raemote_server>

Phone app: <https://github.com/raemote/raemote_connector_ios> — Gitee mirror:
<https://gitee.com/pppkin/raemote_connector_ios>

## License

AGPL-3.0-or-later — see [LICENSE](https://github.com/raemote/raemote_server/blob/main/LICENSE).
