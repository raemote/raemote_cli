# Threat Model

This document describes what Raemote protects, what it explicitly does **not**
protect, and the assumptions behind the device-trust model. It is meant to be
readable by a technical user deciding whether to trust Raemote with access to
their machine.

## Assets

- **Server identity** — the daemon's private key (`~/.raemote/secret.key`).
- **Device trust** — the set of paired device identities (`~/.raemote/authorized_nodes`).
- **Device access scopes** — which apps each paired device may reach
  (`~/.raemote/device_scopes`).
- **Local applications** — the web apps the daemon can proxy to on loopback.
- **Configuration** — `~/.raemote/config.toml`.

## Actors

- **Owner** — the person operating the server. Has shell access; can pair,
  revoke, and read logs.
- **Paired device** — a phone/tablet whose identity is in the trusted set.
- **Pairing link/QR** — a short-lived, high-entropy token plus the server node id.
- **Network** — the Internet and any relays. Untrusted.
- **Relay operators** — forward encrypted packets; cannot read them.

## What Raemote protects

1. **Transport confidentiality and integrity.** All client/server traffic runs
   over iroh (QUIC/TLS), end to end. A relay may forward packets but cannot read
   or modify them.
2. **Access control by device identity.** Only devices that have completed
   pairing may use the serve API. Knowing the server's node id is not enough.
3. **No public exposure.** Installing Raemote does not publish any local app to
   the Internet; apps stay on loopback and are reached only through a paired
   connection.
4. **Bounded pairing window.** The pairing token is 256-bit, compared in
   constant time, expires (default 300 s), and is invalidated after a number of
   failed attempts.
5. **Revocation.** The owner can revoke a device; revoked devices are refused on
   their next request.
6. **Device identity at rest.** The phone's private key lives in the iOS
   Keychain, marked device-only: it is not synced to iCloud and not restored
   onto another device from a backup.
7. **Per-device access scopes.** A paired device can be limited to an allowlist
   of app ports: mint a restricted link with `raemote pair --ports 3000,8080`,
   or change a paired device later with
   `raemote devices access <node-id> --ports … | --all`. Restricted devices do
   not see out-of-scope apps in the catalog and receive `403` when they request
   one directly. The default (a link minted without `--ports`) grants every app.
8. **Device-to-device invitations.** A paired device can mint a **one-time**
   invitation so it can introduce another device. The invitation is 256-bit,
   expires quickly, is consumed on first use, and is minted only by a device
   that is already authorized. An invitation can never grant more than the
   inviter itself has: a request body naming wider ports is rejected with `400`,
   and a bodyless request (what the iOS app sends) inherits the inviter's
   scope exactly.

## What Raemote does NOT protect

- **The applications' own authentication.** Raemote secures *transport and
  device access*. If an app has its own login, that login still applies.
- **A compromised paired device.** Anyone with an unlocked, paired phone has the
  same access that phone has — and no more than that device's scope allows, so
  a phone you restricted to two apps stays inside those two apps.
- **A compromised or malicious server operator.** Raemote runs on the owner's
  machine and trusts the owner.
- **Metadata.** Relay and network observers can see that a connection happened
  and its endpoints, even though the contents are encrypted.
- **Pairing-link phishing.** Anyone who obtains a *live* pairing link before it
  expires can pair a device. Treat the QR/link as a secret and let it expire.

## Attack surface and mitigations

| Surface | Mitigation |
| --- | --- |
| Guessing the pairing token | 256-bit token, constant-time compare, expiry, failed-attempt lockout |
| Stolen/expired pairing link | Short TTL; token expires and is replaceable; post-expiry reuse fails |
| Stolen/expired invitation link | One-time (consumed on first use), short TTL, minted only by an already-authorized device |
| Unauthorized serve connections | Device-identity allowlist; unauthorized connections closed |
| A paired device reaching an app outside its grant | Per-device scope checked on every `/app/` request (403) and on catalog/discovery listing; scope persisted fail-closed |
| A restricted device widening access through an invite | Invite ports must be a subset of the inviter's live scope (400 `beyond_grant`); redemption stores the scope decided at mint time; re-pairing never re-evaluates an existing grant |
| A revoked device with an open connection | Authorization is re-checked on every request; the connection is closed |
| Trust-store tampering/corruption | `~/.raemote` is mode `0700`; a corrupt store fails closed (deny); a corrupt scope line fails closed to *no* apps |
| Resource exhaustion by a paired device | Per-device rate limit and concurrency cap |
| Duplicate/misconfigured daemons | Single-instance OS lock on `~/.raemote/daemon.lock` |
| Local information disclosure via logs | Logs live in `~/.raemote` (mode `0700`), rotating and capped |
| Outbound proxy trust | Optional, explicit; only iroh relay/discovery HTTP(S) is proxied |

## Assumptions and known limitations

- **No independent audit yet.** The model is simple by design, but it has not
  been externally reviewed. Treat early releases accordingly.
- **HTTP-only probing.** Discovery probes local origins over HTTP. HTTPS
  origins are not probed or proxied yet.
- **Relay metadata.** As above, an observer learns that a connection occurred.
- **Device names are display-only.** A device name never affects access; the
  trusted set is keyed on node id alone.
- **macOS visibility.** Without root, the daemon only sees the current user's
  processes (intended: system services stay invisible to discovery).
- **Local host trust.** A local attacker who can read the owner's files can read
  the server key. This is unavoidable for a user-run agent; protect your home
  directory.
- **Per-client state is keyed by node id.** The trusted set, device names, and
  the per-device rate limiter are all keyed on `EndpointId`, and a client's
  identity comes from the authenticated iroh connection (`remote_id`), not from
  anything it sends — so two paired devices can never be confused for one
  another.
- **Pairing lockout is server-wide.** The one piece of state shared across all
  clients is the (single) active pairing token and its failed-attempt counter.
  That is deliberate: a client identity is cheap to regenerate, so a
  per-device counter would be trivially bypassed. The consequence is that
  someone who can reach the bind ALPN and knows the server node id could fail
  enough attempts to revoke the current token — a **denial of pairing, not of
  access** (existing devices keep working). Recovery is immediate: mint a fresh
  token with `raemote pair`.
- **A compromised paired device can invite another device.** Invitations let a
  trusted device add a new one, so a compromised phone can grant itself
  persistence — even after you revoke *that* phone, the device it invited
  remains. This is bounded but not eliminated: invitations are one-time and
  short-lived, both the mint and the redemption are logged (with the inviter),
  an invitation can never exceed the inviter's own scope (a restricted device
  only ever introduces equally-restricted ones), and the owner can revoke the
  invited device like any other. Set `bind.allow_invites = false` to turn the
  feature off entirely.
- **Scopes are port-granular, not path- or user-granular.** A scope names
  upstream ports; two apps sharing one port are one unit, and a scope says
  nothing about routes or logins inside an app. Distinguishing those is the
  app's own authentication job, not Raemote's.
- **A pinned `bind.token` takes its scope from `bind.allow_ports`.** If you pin
  a token in config, the config — not the last `raemote pair --ports` you ran —
  is what the same link will grant after a restart (the daemon warns in the log
  when the two differ). Set `bind.allow_ports` alongside a pinned token to make
  a restricted link survive restarts.

## Security requirements mapping

| Requirement | Status |
| --- | --- |
| Node-id exposure alone is insufficient | Implemented |
| Pairing authorization expires | Implemented |
| Pairing is not permanent access | Implemented |
| Only explicitly trusted identities may access | Implemented |
| A paired device can be limited to a subset of apps | Implemented (port allowlist; invite can never exceed it) |
| Devices are individually revocable | Implemented |
| Communication is authenticated and encrypted | Implemented |
| Server identity persists | Implemented |
| Device trust persists (fail-safe) | Implemented |
| Updates are authenticated | Partial (checksum-verified downloads; no signed releases) |
| Security does not rely on secrecy of the implementation | Intended (open source; license added) |
