# How Raemote works

A one-page explanation, in plain language, of what happens when you install
Raemote, pair your phone, and open an app.

## Two pieces

- **The server** (`raemote`) runs on your computer. It finds the web apps
  already running there and keeps a private connection ready.
- **The app** (Raemote, on your phone) shows those apps and opens them.

There is no account and no cloud service in the middle.

## Pairing: how your phone becomes trusted

Every server and every phone has its own cryptographic identity — a key pair
that is created once and stored locally. When you scan the pairing QR code:

1. The code contains the server's identity and a **short-lived token**.
2. Your phone connects and presents the token.
3. The server checks the token, then remembers **your phone's identity** as
   trusted, and stores it on disk.

From then on, your phone is recognized by its identity — the token is never
needed again. The pairing link is valid only for a short time and can pair more
than one device until it expires; after that it is dead.

> Knowing the server's identity is not enough to get in. Only a device you
> paired is allowed.

You can name, list, and remove trusted devices at any time:

```sh
raemote devices list
raemote devices rename <node-id> "Leo's iPhone"
raemote devices revoke <node-id>
```

Devices you have not named show as `device-<hex>`. The Raemote app can also set
its own name (**About → This device**).

Servers have names too: the app shows the name the server reports (the machine
hostname by default, or `[name]` in the config), and you can set a per-server
alias in the app (Server → Name) that overrides it.

## The connection: direct, encrypted, relay-assisted if needed

Your phone and computer try to talk **directly** to each other. When that isn't
possible (different networks, restrictive firewalls), a public **relay** forwards
the traffic instead.

Either way, the connection is end-to-end encrypted: a relay can see that a
connection happened and its endpoints, but not what is inside it.

## Staying connected

The computer keeps an eye on its own network path. If the library's relay task
stops draining its queue — the log shows `dropping message for relay actor,
channel is full` every 20 seconds or so — or if it has had no relay at all for
15 minutes, `raemoted` rebuilds its endpoint in place: same node id, same
pairing token, same paired devices and app list, fresh sockets. A rebuild waits
until no device is connected, so it never cuts a session short, and repeats back
off (5 minutes, doubling, capped at 30). `raemote status` reports how many times
it happened and why.

## Discovery: finding your apps

The server periodically looks at which processes on your computer are listening
on a local port, probes each one with a single HTTP request, and lists the ones
that look like web pages. Nothing is port-scanned, and nothing is exposed to the
public Internet — the apps stay on your computer and are reached only through a
paired device.

The list is automatic and temporary. You can:

- add an app that discovery missed: `raemote apps add myserver 8080`;
- hide something discovery shouldn't have listed: `raemote apps hide 127.0.0.1:10808`.

## What Raemote does *not* do

- It does not put your apps on the public Internet.
- It does not replace an app's own login — if an app has its own password, that
  still applies.
- It does not protect a compromised phone: anyone with your unlocked, paired
  phone has the same access the phone does.

See [`threat-model.md`](threat-model.md) for the full security model.
