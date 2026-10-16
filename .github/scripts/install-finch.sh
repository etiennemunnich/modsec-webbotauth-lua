#!/usr/bin/env bash
# install-finch.sh: Finch on a GitHub-hosted Ubuntu 24.04 runner, so CI runs
# the container suites on the same tool as a laptop. The live scripts take the
# CLI from $DOCKER; on Linux, Finch runs as root: DOCKER="sudo finch".
#
# Finch's Ubuntu package (https://runfinch.com/docs/managing-finch/linux/installation/)
# is pinned here by version and by the SHA-256 GitHub publishes for the
# release asset, rather than taken from the floating apt repository.
set -euo pipefail
VERSION=1.19.0
SHA256=efb6e5d5c5078c1797290978c5f92cbda6677df7eda1d620f27666767c50440c
DEB=runfinch-finch_${VERSION}_amd64.deb

curl -fsSL --retry 3 --max-time 300 -o "/tmp/$DEB" "https://github.com/runfinch/finch/releases/download/v${VERSION}/$DEB"
echo "$SHA256  /tmp/$DEB" | sha256sum -c -
# The runner image ships Docker, whose containerd.io package conflicts with the
# distribution's containerd that Finch depends on: remove Docker first, so the
# container suites run on Finch alone.
mapfile -t docker_pkgs < <(dpkg-query -W -f='${Package}\n' 'docker-*' 'containerd*' 'moby-*' 2>/dev/null || true)
if [ ${#docker_pkgs[@]} -gt 0 ]; then
  sudo systemctl stop docker.socket docker containerd 2>/dev/null || true
  sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "${docker_pkgs[@]}"
fi
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "/tmp/$DEB"
sudo systemctl daemon-reload
sudo systemctl enable --now containerd finch-buildkit
sudo finch version
