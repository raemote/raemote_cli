#!/usr/bin/env bash
# Mirror a GitHub release's assets to a Gitee release.
#
# `install.sh` prefers Gitee, and GitHub is unreliable on some networks
# (mainland China especially), so a release that only exists on GitHub makes the
# one-liner fall back to a flaky path. The `sync-release-gitee` workflow runs
# this on every published release; run it by hand to backfill an older one:
#
#   GITEE_TOKEN=... scripts/sync-gitee.sh v0.1.0 dist
#
# Env:
#   GITEE_TOKEN        required. Gitee personal access token with `projects`.
#   GITEE_REPO         default: pppkin/raemote_cli
#   RELEASE_NAME       default: the tag
#   RELEASE_BODY_FILE  optional markdown body for the Gitee release
#   PRERELEASE         default: false
#   REPLACE            1 re-uploads assets that are already attached
set -euo pipefail

tag=${1:?usage: sync-gitee.sh <tag> <assets-dir>}
assets_dir=${2:?usage: sync-gitee.sh <tag> <assets-dir>}
: "${GITEE_TOKEN:?GITEE_TOKEN is required (a Gitee token with the 'projects' scope)}"

repo=${GITEE_REPO:-pppkin/raemote_cli}
api=${GITEE_API:-https://gitee.com/api/v5}/repos/$repo
name=${RELEASE_NAME:-$tag}
prerelease=${PRERELEASE:-false}
replace=${REPLACE:-0}

[ -d "$assets_dir" ] || { echo "error: no such directory: $assets_dir" >&2; exit 1; }

# Gitee rejects an empty `body` parameter ("body is missing"), and our own
# GitHub releases don't set one, so fall back to a line describing the mirror.
body_file=${RELEASE_BODY_FILE:-}
tmp_body=
if [ -z "$body_file" ] || [ ! -s "$body_file" ]; then
    tmp_body=$(mktemp)
    printf 'Mirrored from the GitHub release %s.\n' "$tag" >"$tmp_body"
    body_file=$tmp_body
fi
# shellcheck disable=SC2064
trap '[ -n "$tmp_body" ] && rm -f "$tmp_body"' EXIT

# The token goes in the form body (never a URL), so it can't leak into a log.
# Errors print the request and the API's own message, minus the token.
api_call() { # method url [curl args...]
    local method=$1 url=$2; shift 2
    local out code
    out=$(mktemp)
    code=$(curl -sS --max-time 1800 --connect-timeout 30 -X "$method" "$url" "$@" -o "$out" -w '%{http_code}' || echo 000)
    if [ "$code" = 000 ] || [ "$code" -ge 400 ]; then
        printf 'error: %s %s -> HTTP %s\n' "$method" "$url" "$code" >&2
        head -c 500 "$out" >&2 || true
        printf '\n' >&2
        rm -f "$out"
        return 1
    fi
    cat "$out"
    rm -f "$out"
}

jq() { python3 -c "$1"; }

# Uploading ~10 MB per asset from a GitHub runner to Gitee takes minutes and
# occasionally drops, so give a failed call one more go before giving up.
retry() {
    if ! "$@"; then
        printf '  retrying once...\n' >&2
        "$@"
    fi
}

# ---------------------------------------------------------------- the release
release_id=$(api_call GET "$api/releases/tags/$tag" \
    -G --data-urlencode "access_token=$GITEE_TOKEN" \
    | jq 'import json,sys
d = json.load(sys.stdin)
print("" if not isinstance(d, dict) else d.get("id", ""))')

if [ -z "$release_id" ]; then
    release_id=$(retry api_call POST "$api/releases" \
        --data-urlencode "access_token=$GITEE_TOKEN" \
        --data-urlencode "tag_name=$tag" \
        --data-urlencode "target_commitish=$tag" \
        --data-urlencode "name=$name" \
        --data-urlencode "body@$body_file" \
        --data-urlencode "prerelease=$prerelease" \
        | jq 'import json,sys;print(json.load(sys.stdin).get("id", ""))')
    [ -n "$release_id" ] || { echo "error: the Gitee API did not return a release id" >&2; exit 1; }
    echo "created Gitee release for $tag (id $release_id)"
else
    retry api_call PATCH "$api/releases/$release_id" \
        --data-urlencode "access_token=$GITEE_TOKEN" \
        --data-urlencode "tag_name=$tag" \
        --data-urlencode "name=$name" \
        --data-urlencode "body@$body_file" \
        --data-urlencode "prerelease=$prerelease" >/dev/null
    echo "updated Gitee release for $tag (id $release_id)"
fi

# ------------------------------------------------------------ the attachments
attachments() {
    api_call GET "$api/releases/$release_id/attach_files" \
        -G --data-urlencode "access_token=$GITEE_TOKEN" \
        | jq 'import json,sys
for a in (json.load(sys.stdin) or []):
    print(a.get("id"), a.get("name"))'
}

upload() { # file
    local file=$1 filename existing
    filename=$(basename "$file")
    existing=$(attachments | awk -v n="$filename" '$2 == n { print $1 }')

    if [ -n "$existing" ]; then
        if [ "$replace" != "1" ]; then
            echo "  kept $filename (already attached; REPLACE=1 re-uploads)"
            return 0
        fi
        local id
        for id in $existing; do
            retry api_call DELETE "$api/releases/$release_id/attach_files/$id" \
                --data-urlencode "access_token=$GITEE_TOKEN" >/dev/null
        done
    fi

    retry api_call POST "$api/releases/$release_id/attach_files" \
        -F "access_token=$GITEE_TOKEN" -F "file=@$file" >/dev/null
    echo "  uploaded $filename"
}

shopt -s nullglob
assets=("$assets_dir"/*)
[ ${#assets[@]} -gt 0 ] || { echo "error: no assets found in $assets_dir" >&2; exit 1; }

echo "mirroring ${#assets[@]} asset(s) to Gitee ($repo):"
for asset in "${assets[@]}"; do
    upload "$asset"
done

# --------------------------------------------------------------------- verify
listing=$(attachments)
missing=0
for asset in "${assets[@]}"; do
    filename=$(basename "$asset")
    if printf '%s\n' "$listing" | awk -v n="$filename" '$2 == n { found = 1 } END { exit !found }'; then
        echo "  ok      $filename"
    else
        echo "  MISSING $filename" >&2
        missing=1
    fi
done
[ "$missing" = 0 ] || { echo "error: the Gitee release is missing assets" >&2; exit 1; }

echo "https://gitee.com/$repo/releases/tag/$tag"
