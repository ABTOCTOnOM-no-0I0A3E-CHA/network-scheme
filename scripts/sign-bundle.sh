#!/usr/bin/env bash
# Signs an update bundle with the maintainer's OFFLINE minisign key (never in CI or on a server),
# writes BUNDLE.minisig next to it and checks it against the public key nmsctl is built with.
# Key pair: minisign -G -p minisign.pub -s minisign.key (keep minisign.key offline); nmsctl gets
# the public key line at build time: -ldflags "-X main.releaseKey=RWQ..." (MINISIGN_PUBLIC_KEY in CI).
# usage: sign-bundle.sh BUNDLE SECRET_KEY PUBLIC_KEY
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 BUNDLE SECRET_KEY PUBLIC_KEY" >&2; exit 2; }
bundle=$1 seckey=$2 pubkey=$3
command -v minisign >/dev/null || { echo "minisign is not installed" >&2; exit 1; }
tar -xOf "$bundle" manifest.json >/dev/null # it is a bundle

# Prehashed signature (the default of minisign >= 0.10; nmsctl accepts no other).
minisign -S -s "$seckey" -m "$bundle" -t "nms update bundle $(basename "$bundle")"
sed -n 2p "$bundle.minisig" | grep -q '^RU' || { echo "not a prehashed signature: upgrade minisign" >&2; exit 1; }
minisign -V -p "$pubkey" -m "$bundle"
