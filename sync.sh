#!/usr/bin/env bash
# Copies fount-broker's link and frame packages here unchanged but for the
# import path, so the live run tests the broker's own code. SOURCE records the
# commit and whether its tree was clean.
#
#   [BROKER_REPO=~/Desktop/code/fount-broker-supervisor] ./sync.sh
set -euo pipefail
cd "$(dirname "$0")"
SRC="${BROKER_REPO:-$HOME/Desktop/code/fount-broker-supervisor}"
rm -rf link frame attested
mkdir link frame attested
rewrite() { sed 's#github.com/fount-labs/fount-broker/internal/#github.com/zeke-02/link-probe/#' "$1" > "$2"; }
for f in link.go tinfoil.go unattested.go upgrade.go link_test.go upgrade_test.go; do
  rewrite "$SRC/internal/link/$f" "link/$f"
done
for f in frame.go frame_test.go; do rewrite "$SRC/internal/frame/$f" "frame/$f"; done
rewrite "$SRC/internal/attested/attested.go" attested/attested.go
gofmt -w link frame attested
{
  git -C "$SRC" rev-parse HEAD
  git -C "$SRC" status --porcelain -- internal/link internal/frame internal/attested | sed 's/^/dirty: /'
} > SOURCE
cat SOURCE
