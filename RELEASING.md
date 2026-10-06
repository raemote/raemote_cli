# Releasing

Releases are built by GitHub Actions and attached to a GitHub Release. The
`install.sh` one-liner resolves the latest release (Gitee first, then GitHub) so
it works once at least one of them has a release with the expected assets.

## Asset contract

Each release must include, at minimum:

```
raemote-darwin-arm64.tar.gz
raemote-darwin-x86_64.tar.gz
raemote-linux-x86_64.tar.gz
raemote-linux-arm64.tar.gz
checksums.txt
```

Each tarball contains the two binaries, `raemote` and `raemoted`, at the archive
root. Asset names omit the version so `releases/latest/download/<asset>` works.

## Steps

1. Bump the version in `raemote_cli/Cargo.toml` and commit it.
2. Tag and push:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. `.github/workflows/release.yml` runs on `v*` tags: it builds the four
   targets on GitHub runners (macOS 14 for both darwin targets; Ubuntu x86_64
   and Ubuntu arm64 for Linux), packages them, writes `checksums.txt`, and
   attaches everything to the GitHub Release for that tag.

4. Sanity-check the release page: four tarballs + `checksums.txt`.

5. **The Gitee mirror is automatic.** When the release workflow finishes,
   [`sync-release-gitee.yml`](.github/workflows/sync-release-gitee.yml) runs (it
   triggers on `workflow_run`, not `release: published` — a release created with
   the automatic `GITHUB_TOKEN` does not fire that event for other workflows)
   and
   copies the GitHub release (name, notes and assets) to a Gitee release for the
   same tag. This matters because `install.sh` prefers Gitee and GitHub is
   unreliable on some networks (mainland China especially), so a release that
   only exists on GitHub makes the one-liner fall back to a flaky path — or
   fail. It needs a **`GITEE_TOKEN` repository secret** (a Gitee personal access
   token with the `projects` scope); check the run, and if it failed the release
   still works everywhere GitHub is reachable.

   Backfill or re-sync a tag by hand:

   ```sh
   gh workflow run sync-release-gitee.yml -f tag=v0.1.0   # -f replace=true to re-upload
   ```

   Without CI, mirror from the downloaded tarballs:

   ```sh
   GITEE_TOKEN=... scripts/sync-gitee.sh v0.1.0 dist
   ```

   Gitee release assets don't need re-signing — `checksums.txt` covers the
   tarballs and the installer verifies it whichever source it used.

   Two things to know: the mirror takes roughly 10–20 minutes (a GitHub runner
   uploads ~45 MB to Gitee at ~130 KB/s, and the script allows 30 min per asset
   with one retry), and Gitee rejects an *empty* release body, so a release
   without notes is mirrored with a one-line fallback instead.

6. Verify the one-liner on a clean machine (fresh `HOME` is enough):

   ```sh
   curl -fsSL https://github.com/raemote/raemote_cli/raw/main/install.sh | sh
   raemote status
   ```

   (If only GitHub has the release, the installer falls back to it
   automatically. Test both entry points when it matters:
   `https://gitee.com/pppkin/raemote_cli/raw/main/install.sh`.)

## Manual fallback

No CI is required. On each platform:

```sh
scripts/package.sh                       # host target
scripts/package.sh x86_64-apple-darwin   # cross-build (needs rustup target add)
```

This writes `dist/raemote-<os>-<arch>.tar.gz` and `dist/checksums.txt`. Upload
those files as release assets (Gitee or GitHub).

## Installer resolution order

`install.sh` resolves the latest release in this order:

1. Gitee (`pppkin/raemote_cli`), using the Gitee releases API — needs a Gitee
   release with the assets.
2. GitHub (`raemote/raemote_cli`), using
   `releases/latest/download/<asset>` — needs a GitHub release.

Override with `--source gitee|github`, `--tag <tag>`, or `--base-url <url>`.

## Pre-release checklist

- [ ] `cargo test` and `cargo clippy --all-targets` are green.
- [ ] iOS builds clean and its tests pass.
- [ ] Version bumped and tagged.
- [ ] Release has all four tarballs + `checksums.txt`.
- [ ] `install.sh` verified against the published release.
- [ ] The manual checklist in [`testing.md`](testing.md) has been run on a real
      device.
