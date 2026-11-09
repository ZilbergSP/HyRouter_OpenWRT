#!/usr/bin/env bash
# Builds HyRouter's packages for OpenWrt:
#
#   build/package.sh VERSION OUT
#
# For every target it builds hyrouterd and puts it with the procd service
# and the sysupgrade list into a tree (OUT/tree/<package>_<arch>), then
# packs the .ipk of OpenWrt 24.10 (opkg) into OUT/packages. The .apk of
# OpenWrt 25.x are made from the same trees by build/apk.sh inside an
# Alpine container, which has apk-tools 3 with mkpkg.
set -euo pipefail

VERSION=$1
mkdir -p "$2"
OUT=$(cd "$2" && pwd)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
URL=https://github.com/ZilbergSP/HyRouter_OpenWRT
DEPENDS="kmod-nft-tproxy kmod-nft-socket kmod-nft-queue ca-bundle"

# package GOARCH extra-environment opkg-architectures...
TARGETS=(
	"hyrouter arm64 - aarch64_cortex-a53 aarch64_cortex-a72 aarch64_generic"
	"hyrouter amd64 - x86_64"
	"hyrouter-lite mipsle GOMIPS=softfloat mipsel_24kc"
	"hyrouter-lite arm GOARM=7 arm_cortex-a7_neon-vfpv4 arm_cortex-a7 arm_cortex-a9 arm_cortex-a15_neon-vfpv4"
)

rm -rf "${OUT:?}/bin" "${OUT:?}/tree" "${OUT:?}/packages" "${OUT:?}/zapret2"
mkdir -p "$OUT/bin" "$OUT/tree" "$OUT/packages"

# zapret2 (build/deps.json): nfqws2, its Lua libraries and fake payloads
# for the DPI bypass, from the release checked by its SHA-256.
deps="$ROOT/build/deps.json"
zver=$(jq -r .zapret2.version "$deps")
curl -fsSL --retry 4 --retry-all-errors "$(jq -r .zapret2.url "$deps")" -o "$OUT/zapret2.zip"
echo "$(jq -r .zapret2.sha256 "$deps")  $OUT/zapret2.zip" | sha256sum -c -
unzip -q "$OUT/zapret2.zip" -d "$OUT/zapret2"
ZDIR="$OUT/zapret2/zapret2-$zver"

# zarch is zapret2's binary folder of a GOARCH.
zarch() {
	case $1 in
	arm64) echo linux-arm64 ;;
	amd64) echo linux-x86_64 ;;
	mipsle) echo linux-mipsel ;;
	arm) echo linux-arm ;;
	esac
}

tarit() { tar --owner=0 --group=0 --numeric-owner --format=gnu "$@"; }

for t in "${TARGETS[@]}"; do
	read -r pkg goarch extra archs <<<"$t"
	bin="$OUT/bin/$pkg-$goarch"
	tags=()
	other=hyrouter-lite
	desc="HyRouter: the LAN routed through Hysteria 2 and VLESS servers by rules for devices and sites, with a web interface"
	if [ "$pkg" = hyrouter-lite ]; then
		tags=(-tags lite)
		other=hyrouter
		desc="HyRouter Lite: the LAN routed through Hysteria 2 servers by rules for devices and sites, for routers with 128-256 MB of memory"
	fi
	(
		if [ "$extra" != - ]; then export "${extra%%=*}=${extra#*=}"; fi
		cd "$ROOT"
		CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build "${tags[@]}" -trimpath \
			-ldflags "-s -w -X main.version=$VERSION" -o "$bin" ./cmd/hyrouterd
	)
	for arch in $archs; do
		tree="$OUT/tree/${pkg}_$arch"
		mkdir -p "$tree/root/usr/bin" "$tree/root/etc/init.d" "$tree/root/lib/upgrade/keep.d" "$tree/control"
		install -m 0755 "$bin" "$tree/root/usr/bin/hyrouterd"
		install -m 0755 "$ROOT/build/openwrt/hyrouter.init" "$tree/root/etc/init.d/hyrouter"
		install -m 0755 "$ROOT/build/openwrt/hyrouter-guard.init" "$tree/root/etc/init.d/hyrouter-guard"
		z="$tree/root/usr/share/hyrouter/zapret"
		mkdir -p "$z/lua" "$z/blobs"
		install -m 0755 "$ZDIR/binaries/$(zarch "$goarch")/nfqws2" "$z/nfqws2"
		for f in zapret-lib.lua zapret-antidpi.lua zapret-auto.lua; do
			install -m 0644 "$ZDIR/lua/$f" "$z/lua/$f"
		done
		for f in tls_clienthello_www_google_com.bin quic_initial_www_google_com.bin tls_clienthello_vk_com.bin; do
			install -m 0644 "$ZDIR/files/fake/$f" "$z/blobs/$f"
		done
		echo /etc/hyrouter/ >"$tree/root/lib/upgrade/keep.d/hyrouter"
		install -m 0755 "$ROOT/build/openwrt/postinst" "$ROOT/build/openwrt/prerm" "$tree/control/"
		size=$(du -sb "$tree/root" | cut -f1)
		cat >"$tree/control/control" <<EOF
Package: $pkg
Version: $VERSION-1
Depends: ${DEPENDS// /, }
Conflicts: $other
Source: $URL
SourceName: hyrouter
Section: net
URL: $URL
Architecture: $arch
Installed-Size: $size
Description: $desc
EOF
		# For build/apk.sh (sourced by /bin/sh).
		cat >"$tree/meta" <<EOF
name='$pkg'
version='$VERSION-r1'
arch='$arch'
description='$desc'
url='$URL'
depends='$DEPENDS !$other'
EOF
		(cd "$tree/control" && tarit -czf ../control.tar.gz ./control ./postinst ./prerm)
		(cd "$tree/root" && tarit -czf ../data.tar.gz .)
		echo 2.0 >"$tree/debian-binary"
		(cd "$tree" && tarit -czf "$OUT/packages/${pkg}_${VERSION}-1_$arch.ipk" ./debian-binary ./data.tar.gz ./control.tar.gz)
		rm "$tree/control.tar.gz" "$tree/data.tar.gz" "$tree/debian-binary"
	done
done
cp "$ROOT/build/apk.sh" "$OUT/apk.sh"
ls -l "$OUT/packages"
