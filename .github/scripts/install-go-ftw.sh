#!/usr/bin/env bash
# install-go-ftw.sh: go-ftw, the CRS test runner, on a GitHub-hosted Ubuntu
# runner, for lua/tests/live/ftw.sh (on a laptop: brew install
# coreruleset/tap/go-ftw). The release tarball
# (https://github.com/coreruleset/go-ftw/releases) is pinned by version and by
# the SHA-256 the release's ftw-checksums.txt publishes for it. The binary
# inside is named ftw, which ftw.sh finds on PATH ($GITHUB_PATH when set, so
# the steps after this one see it; FTW=/path/to/ftw otherwise).
set -euo pipefail
VERSION=2.6.0
SHA256=fd45fcd4b1df80ea18d7bb09dc9905330c8ccc510f6ae53d9791716ad7838b2f
TGZ=ftw_${VERSION}_linux_amd64.tar.gz
DIR=${GOFTW_DIR:-${RUNNER_TEMP:-/tmp}/go-ftw}

mkdir -p "$DIR"
curl -fsSL --retry 3 --max-time 120 -o "$DIR/$TGZ" "https://github.com/coreruleset/go-ftw/releases/download/v${VERSION}/$TGZ"
echo "$SHA256  $DIR/$TGZ" | sha256sum -c -
tar -xzf "$DIR/$TGZ" -C "$DIR" ftw
rm -f "$DIR/$TGZ"
if [ -n "${GITHUB_PATH:-}" ]; then echo "$DIR" >> "$GITHUB_PATH"; fi
"$DIR/ftw" -v
