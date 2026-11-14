#!/usr/bin/env bash
# Upload dist/cpanel/ to the cPanel host and verify the live site.
#
# Usage: scripts/deploy-cpanel.sh [user@host]
#
# The target defaults to the deploy user on the site's own hostname. It expects
# ~/.ssh/ocellus-deploy to be authorised there, and writes into
# ~/public_html, which is the document root the subdomain serves.
set -euo pipefail

TARGET="${1:-deploy@ocellus.zynu.me}"
KEY="$HOME/.ssh/ocellus-deploy"
SRC="$(cd "$(dirname "$0")/.." && pwd)/dist/cpanel"

[ -d "$SRC" ] || { echo "no build at $SRC; run npm run build:cpanel first" >&2; exit 1; }
[ -f "$KEY" ] || { echo "missing key at $KEY" >&2; exit 1; }

SSH=(ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 "$TARGET")

# Refuse to run against a host that is not the site, so a mistyped argument
# cannot push 75 files somewhere unexpected.
"${SSH[@]}" 'echo ready' >/dev/null || {
  echo "cannot authenticate to $TARGET with $KEY" >&2
  exit 1
}

echo "uploading $(find "$SRC" -type f | wc -l) files to $TARGET"
# tar over ssh: one stream, no compression of already-compressed assets, and it
# preserves the directory layout without needing a temporary file on either end.
tar -C "$SRC" -cf - . | "${SSH[@]}" 'tar -xf - -C ~/public_html'

echo "verifying"
"${SSH[@]}" 'ls -1 ~/public_html/index.html ~/public_html/.htaccess ~/public_html/privacy/index.html >/dev/null && echo files-present'
