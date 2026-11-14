#!/usr/bin/env bash
# Upload dist/cpanel/ to the cPanel host and verify the live site.
#
# Usage: scripts/deploy-cpanel.sh <user@host> [docroot]
#
#   scripts/deploy-cpanel.sh zynu@ocellus.zynu.me
#   scripts/deploy-cpanel.sh zynu@148.113.1.25 ~/public_html
#
# The docroot is optional. When it is omitted the script asks the account where
# the domain is actually served from, because cPanel puts the primary domain in
# ~/public_html and an addon or subdomain in its own directory. Guessing wrong
# uploads 75 files into a folder nothing reads, so the answer is looked up
# rather than assumed.
#
# It expects ~/.ssh/ocellus-deploy to be authorised on that account.
set -euo pipefail

TARGET="${1:?usage: scripts/deploy-cpanel.sh <user@host> [docroot]}"
DOCROOT="${2:-}"
KEY="$HOME/.ssh/ocellus-deploy"
SRC="$(cd "$(dirname "$0")/.." && pwd)/dist/cpanel"
SITE="https://ocellus.zynu.me"

[ -d "$SRC" ] || { echo "no build at $SRC; run npm run build:cpanel first" >&2; exit 1; }
[ -f "$KEY" ] || { echo "missing key at $KEY" >&2; exit 1; }

SSH=(ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 "$TARGET")

# Fail before touching anything if the key is not accepted. The error from ssh is
# printed rather than swallowed, because "Permission denied" and "connection
# refused" need completely different fixes.
if ! "${SSH[@]}" 'echo ready' >/dev/null 2>/tmp/ocellus-ssh.err; then
  echo "cannot authenticate to $TARGET with $KEY" >&2
  sed 's/^/  /' /tmp/ocellus-ssh.err >&2
  exit 1
fi

if [ -z "$DOCROOT" ]; then
  # cPanel records each domain's document root. Asking is better than assuming
  # ~/public_html, which is only correct for the account's primary domain.
  DOCROOT="$("${SSH[@]}" 'uapi DomainInfo list_domains 2>/dev/null | sed -n "s/.*documentroot: *//p" | head -1' 2>/dev/null || true)"
  if [ -z "$DOCROOT" ]; then
    # The two layouts cPanel uses, in its own order.
    DOCROOT="$("${SSH[@]}" 'if [ -d "$HOME/ocellus.zynu.me" ]; then echo "$HOME/ocellus.zynu.me"; else echo "$HOME/public_html"; fi')"
  fi
fi

echo "target   $TARGET"
echo "docroot  $DOCROOT"
echo "files    $(find "$SRC" -type f | wc -l)"

# Confirm the directory exists and is writable before sending anything.
"${SSH[@]}" "test -d \"$DOCROOT\" && test -w \"$DOCROOT\"" || {
  echo "$DOCROOT is missing or not writable on $TARGET" >&2
  exit 1
}

# Keep the previous index until the new files are in place, so a dropped
# connection cannot leave the site half-uploaded.
echo "uploading"
tar -C "$SRC" -cf - . | "${SSH[@]}" "
  mkdir -p \"$DOCROOT/.ocellus-previous\" &&
  if [ -f \"$DOCROOT/index.html\" ]; then cp -a \"$DOCROOT/index.html\" \"$DOCROOT/.ocellus-previous/\" 2>/dev/null || true; fi &&
  tar -xf - -C \"$DOCROOT\"
"

echo "checking the files landed"
"${SSH[@]}" "ls -1 \"$DOCROOT/index.html\" \"$DOCROOT/.htaccess\" \"$DOCROOT/privacy/index.html\" >/dev/null && echo present"

# A successful upload says nothing about the site serving it. These are the
# three things that go wrong after a good upload: the wrong docroot, a caching
# layer holding the old page, and .htaccess being ignored.
echo "checking $SITE"
fail=0
for path in "" "privacy/" "terms/" "checks/" "method/" "about/"; do
  code="$(curl -s -o /tmp/ocellus-live.html -w '%{http_code}' -m 20 -L "$SITE/$path")"
  size="$(wc -c < /tmp/ocellus-live.html)"
  if [ "$code" != "200" ]; then
    echo "  /$path -> $code" >&2
    fail=1
  elif [ "$size" -lt 2000 ]; then
    echo "  /$path -> 200 but only $size bytes, which is a directory index rather than a page" >&2
    fail=1
  else
    echo "  /$path -> 200, $size bytes"
  fi
done

if grep -qi "Index of /" /tmp/ocellus-live.html; then
  echo "the host is serving a directory listing, so the docroot is not where the files went" >&2
  fail=1
fi

[ "$fail" -eq 0 ] && echo "live" || { echo "uploaded, but the site did not verify" >&2; exit 1; }
