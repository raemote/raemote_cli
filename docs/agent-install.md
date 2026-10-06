# Installing Raemote from an AI agent

> Requires a Raemote release that includes `pair` and `doctor` (**0.2.0+**).
> On 0.1.0, use `raemote qr` and `raemote status` instead.

Raemote is designed to be installed by an AI agent acting on the user's machine.
Every step is non-interactive and machine-verifiable.

## Contract

- **Non-interactive** — no prompts; every option is a flag.
- **Idempotent** — safe to re-run. Re-installing upgrades the binaries in place
  and preserves the server identity and paired devices.
- **Machine-readable** — `--json` writes a single JSON object to **stdout**;
  human progress goes to **stderr**.
- **Fail-loud** — `install.sh` and `raemote doctor` exit **non-zero** on failure.

## Step 1 — install

```sh
curl -fsSL https://github.com/raemote/raemote_cli/raw/main/install.sh \
  | sh -s -- --json
```

stdout:

```json
{"installed":true,"version":"0.1.0","bin_dir":"/home/you/.local/bin","service":true,"node_id":"<hex>","uri":"raemote://bind?node=<hex>&token=<hex>&exp=<unix>"}
```

- `"service":false` → the background service was not installed; run
  `"<bin_dir>/raemote" service install`.
- `bin_dir` may not be on `PATH`; call the binary by absolute path.
- With `--no-service` the installer skips the service (and omits `uri`); start
  the daemon with `"<bin_dir>/raemote" start`.

Useful flags: `--no-service`, `--bin-dir DIR`, `--proxy URL`, `--source gitee|github`,
`--tag TAG`, `--quiet`.

## Step 2 — verify

```sh
"<bin_dir>/raemote" doctor --json
```

```json
{"ok":true,"checks":[{"name":"daemon","status":"ok","detail":"running"},{"name":"relay","status":"ok","detail":"reachable via 1.2.3.4:443"}]}
```

- Exit `0` and `"ok": true` → healthy.
- Exit `1` → read each check's `detail` and `hint`; `status` is `ok`/`warn`/`fail`.

## Step 3 — pair the user's phone

```sh
"<bin_dir>/raemote" pair --json
```

```json
{"uri":"raemote://bind?node=<hex>&token=<hex>&exp=<unix>","expires_at_unix":1789379492}
```

Show the `uri` to the user, or (in a terminal) run `"<bin_dir>/raemote" pair` to
print a scannable QR code. The link is short-lived and can pair more than one
device until it expires.

The user then installs the **Raemote** iOS app, taps **+**, and scans the QR or
pastes the link.

> The `token` is a credential. Show it only to the user who asked, and do not
> write it to shared logs.

## Restrictive networks

If `doctor` reports the relay unreachable, install or configure an outbound
proxy and restart:

```sh
"<bin_dir>/raemote" config set network.proxy http://host:port
"<bin_dir>/raemote" restart
```

## Reversing it

```sh
curl -fsSL https://github.com/raemote/raemote_cli/raw/main/install.sh \
  | sh -s -- --uninstall          # add --purge to also delete ~/.raemote
```

See the [README](../README.md) for the common commands, or `raemote --help`.
