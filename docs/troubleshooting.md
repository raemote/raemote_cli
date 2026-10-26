# Troubleshooting

Start here — it checks the common causes and tells you what to do:

```sh
raemote doctor
```

Every check prints `ok`, `warn`, or `FAIL` with a hint. Add `--json` for scripts
and `--verbose` for relays and sockets.

If you need to go further, the daemon keeps a log:

```sh
raemote logs -n 50      # recent activity
raemote logs --follow   # stream it live
```

## The phone can't connect

1. On the computer: `raemote status` — is the daemon running with the expected
   paired/connected counts? If not, `raemote start`.
2. In the app: background and reopen it, or tap the refresh/reconnect control.
3. Make sure the phone has internet. The computer must be awake and online.
4. If `doctor` says the relay is unreachable, see *Restrictive networks* below.
5. If the app says it is not authorized, your device may have been revoked —
   pair again with `raemote pair`.

## Check the app directly, without raemote

When the tunnel is the suspect, take it out of the picture. `scripts/lan-http-scan.py`
(from the repository — Python 3, no dependencies, not part of the release
tarballs) scans the network this machine is on, asks every open port for `/`, and
prints what answered:

```sh
scripts/lan-http-scan.py                       # every LAN + common web ports
scripts/lan-http-scan.py --cidr 192.168.1.0/24 --ports 80,8080,3000-3010
scripts/lan-http-scan.py --all                 # also open ports that aren't HTTP
scripts/lan-http-scan.py --json | jq -r '.http[].url'
scripts/lan-http-scan.py --explain 192.168.1.20:3000   # one target, port by port
```

A service you can open in a browser but the scan misses is almost always a
sleeping Wi-Fi device: the first packet to it takes hundreds of milliseconds, so
a one-shot 0.35 s connect probe times out. The scan already retries timed-out
ports on hosts that are awake, with a 3× deadline; `--timeout 1 --retries 2`
goes further. `--explain <ip>:<port>` tells you exactly which of the two
happened (`refused` = host answered, nothing listening; `timed out` = no answer;
`unreachable` = no route), and whether the host is even in the neighbour table.

Open one of the printed URLs **on the device that can't connect**:

- it loads → the app and the network are fine, and the problem is the tunnel:
  `raemote status`, `raemote doctor`, and the app's Connection Logs;
- nothing on the list → the app either isn't running or is bound to `127.0.0.1`,
  which a scan from another machine cannot see (by design). Check on the machine
  itself: `raemote discover --verbose` lists every local listener and why it was
  skipped, and `curl -I http://127.0.0.1:<port>` talks to it directly.

Only private ranges are scanned by default, and the only traffic is a TCP connect
plus one `GET /` per open port. On macOS 15+ your terminal needs *System Settings
→ Privacy & Security → Local Network*, or every host looks dead.

## It worked before and now nothing connects

The daemon heals its own network endpoint, so first check whether it had to:
`raemote status` shows `relay state` and `<n> rebuild(s), last <reason> at
<when>`; `raemote doctor` repeats both checks.

If the log has long runs of

```
WARN iroh::socket::transports::relay: dropping message for relay actor, channel is full
```

every 20–25 seconds, the relay task inside the networking library wedged. That
is what the watchdog is for: it rebuilds the endpoint (same pairing, same
devices) after a few of those warnings, or after 15 minutes without any relay.
A rebuild is invisible to a phone that is already connected — it waits for the
device to leave first — and a phone that reconnects a moment later reaches the
new endpoint automatically.

If rebuilds keep climbing, the network is the problem, not the daemon: check
`raemote doctor` for the relay probe under *Restrictive networks* below.

## No apps appear

- The app must answer an HTTP request at `/` like a web page. If it only serves
  an API or a non-HTTP protocol, it won't be listed.
- Confirm it is reachable on the computer: open `http://127.0.0.1:<port>` there.
- Run `raemote discover`, then `raemote apps list`.
- Ask why: `raemote discover --verbose` lists every listening socket that was
  *not* exposed and the reason (denylisted port or process, a specific-address
  bind, a page with no title, unreachable, …). That answers most cases at once.
- Listeners raemote can't map to a process are picked up too: raemote reads the
  kernel's socket table as well as the process list, so a root-owned `nginx` in
  front of your app, or a container port-forward (Docker/podman/`pasta`, common
  with Distrobox and on the Steam Deck), is still discovered — with the page
  title as its name, since there is no process name to fall back on. Set
  `discovery.include_unattributed = false` to ignore them again.
- A bind to a *specific* address (e.g. `listen 192.168.1.5:8080`) is ignored
  while `discovery.loopback_only` is on (the default). Bind `0.0.0.0`/loopback
  instead, or turn it off: `raemote config set discovery.loopback_only false`.
- On macOS, only apps owned by your user are visible (system services stay
  private). Docker-published apps are user-owned and *are* visible.
- Still missing? Add it by hand: `raemote apps add myserver 8080`.

## Something is listed that isn't a web app

Local proxies (for example xray/sing-box) are excluded automatically. If
something else slips through:

```sh
raemote apps hide 127.0.0.1:10808     # or: raemote apps hide <name>
raemote apps unhide 127.0.0.1:10808
```

## The pairing link stopped working

Pairing links are intentionally short-lived. Mint a new one:

```sh
raemote pair
```

If you want a link that stays valid across restarts, see the long-lived pairing
note in the [README](../README.md) (pin `[bind] token` in the config).

## I can't tell my devices apart

Unnamed devices show as `device-<hex>`, so give them names:

```sh
raemote devices list
raemote devices rename <node-id> "Leo's iPhone"
```

The phone can also name itself (**About → This device**), and it sends its name
whenever it pairs. Names are for your convenience only — they never affect who
can connect.

## Restrictive networks (relay unreachable)

Some networks block the infrastructure that Raemote uses. Configure an outbound
proxy (HTTP CONNECT; SOCKS URLs are accepted and treated as HTTP):

```sh
raemote config set network.proxy http://host:port
raemote restart
```

`doctor` will then check the proxy instead of probing the relay directly.

## The service doesn't start at login

```sh
raemote service install
raemote service status
```

On Linux, the installer runs `loginctl enable-linger` so the user service
survives logout; if that failed, run it manually.

## An app shows an error page

- **"Couldn't reach the app"** — the app stopped or moved. Start it on the
  computer, then refresh the app list.
- **"took too long to respond"** — the app is busy; try again.
- **"unknown app"** — the app is gone from the list; tap refresh in the app.

## HTTPS apps

Discovery and proxying are HTTP-only for now. An app that only speaks HTTPS is
not reachable through Raemote yet; add it manually only if it also serves HTTP.

## Getting help

Gather `raemote doctor --json` and a few lines from `raemote logs`, then open an
issue: <https://github.com/raemote/raemote_cli/issues>. For security problems,
follow [`SECURITY.md`](../SECURITY.md) instead of opening a public issue.
