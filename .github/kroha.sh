#!/usr/bin/env bash
# Builds prizrak-kroha, the lighter router build of the core, for one Linux
# target: the plain binary and, when upx is installed, the same binary packed
# with UPX. Both are gzipped the way the prizrak-core assets are:
#
#   <out>/prizrak-kroha-linux-<target>-<version>.gz
#   <out>/prizrak-kroha-linux-<target>-compressed-<version>.gz
#
# usage: .github/kroha.sh <target> <version> [out-dir]
#   target   amd64 | arm64 | armv7 | mips-softfloat | mipsle-softfloat
#   version  the release version, e.g. v1.19.34-r4; the binary reports
#            <version>-kroha
#   out-dir  defaults to bin
#
# Environment: BUILDTIME overrides the build time, KROHA_UPX=0 skips the
# packed variant, KROHA_UPX=1 makes a missing upx an error.
set -euo pipefail

# Everything a router needs stays; these leave the build. gVisor is left out
# by not setting with_gvisor: the TUN stacks mips (the default) and system stay.
KROHA_TAGS="with_low_memory,no_tailscale,no_zerotier,no_easytier,no_openvpn,no_masque,no_mieru,no_sudoku,no_trusttunnel,no_shadowquic,no_snell,no_ssr,no_anytls"

if [ "$#" -lt 2 ]; then
	sed -n '2,16p' "$0" >&2
	exit 2
fi
target=$1
version=$2
out=${3:-bin}

case "$target" in
amd64) goarch=amd64; export GOAMD64=v1 ;;
arm64) goarch=arm64 ;;
armv7) goarch=arm; export GOARM=7 ;;
mips-softfloat) goarch=mips; export GOMIPS=softfloat ;;
mipsle-softfloat) goarch=mipsle; export GOMIPS=softfloat ;;
*)
	echo "unknown target: $target" >&2
	exit 2
	;;
esac
export GOOS=linux GOARCH=$goarch CGO_ENABLED=0

mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$(dirname "$0")/.."

name="prizrak-kroha-linux-$target"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

go build -trimpath -tags "$KROHA_TAGS" \
	-ldflags "-X 'github.com/metacubex/mihomo/constant.Version=${version}-kroha' -X 'github.com/metacubex/mihomo/constant.BuildTime=${BUILDTIME:-$(date -u)}' -w -s -buildid=" \
	-o "$work/$name" .
chmod 0755 "$work/$name"
gzip -c "$work/$name" >"$out/$name-$version.gz"

upx_mode=${KROHA_UPX:-auto}
if [ "$upx_mode" = 0 ]; then
	exit 0
fi
if ! command -v upx >/dev/null 2>&1; then
	if [ "$upx_mode" = 1 ]; then
		echo "upx not found" >&2
		exit 1
	fi
	echo "upx not found: $name-compressed skipped" >&2
	exit 0
fi
packed="$work/$name-compressed"
cp "$work/$name" "$packed"
if ! upx --lzma "$packed"; then
	echo "upx --lzma failed for $target, retrying with upx -9" >&2
	cp "$work/$name" "$packed"
	upx -9 "$packed"
fi
upx -t "$packed"
gzip -c "$packed" >"$out/$name-compressed-$version.gz"
