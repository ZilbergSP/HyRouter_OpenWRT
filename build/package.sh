#!/usr/bin/env bash
# Builds HyRouter's packages for OpenWrt and for KeeneticOS (Entware):
#
#   build/package.sh VERSION OUT
#
# For every target it builds hyrouterd and puts it with the service
# scripts into a tree (OUT/tree/<package>_<arch>), then packs the .ipk:
# OpenWrt 24.10's opkg and Entware's opkg take the same format. The .apk
# of OpenWrt 25.x are made from the OpenWrt trees (those with a meta file)
# by build/apk.sh inside an Alpine container, which has apk-tools 3 with
# mkpkg.
#
# HYROUTER_TEST_ENTWARE=1 adds a KeeneticOS package for Entware's x64-3.2,
# which no router uses: CI installs it in Entware on Linux.
set -euo pipefail

VERSION=$1
mkdir -p "$2"
OUT=$(cd "$2" && pwd)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
URL=https://github.com/ZilbergSP/HyRouter_OpenWRT
DEPENDS_OPENWRT="kmod-nft-tproxy kmod-nft-socket kmod-nft-queue ca-bundle"
DEPENDS_KEENETIC="iptables ipset ca-bundle"

# platform package GOARCH extra-environment package-architectures...
TARGETS=(
	"openwrt hyrouter arm64 - aarch64_cortex-a53 aarch64_cortex-a72 aarch64_generic"
	"openwrt hyrouter amd64 - x86_64"
	"openwrt hyrouter-lite mipsle GOMIPS=softfloat mipsel_24kc"
	"openwrt hyrouter-lite arm GOARM=7 arm_cortex-a7_neon-vfpv4 arm_cortex-a7 arm_cortex-a9 arm_cortex-a15_neon-vfpv4"
	"keenetic hyrouter-keenetic arm64 - aarch64-3.10"
	"keenetic hyrouter-keenetic-lite mipsle GOMIPS=softfloat mipsel-3.4"
	"keenetic hyrouter-keenetic-lite mips GOMIPS=softfloat mips-3.4"
)
if [ "${HYROUTER_TEST_ENTWARE:-}" = 1 ]; then
	TARGETS+=("keenetic hyrouter-keenetic amd64 - x64-3.2")
fi

rm -rf "${OUT:?}/bin" "${OUT:?}/tree" "${OUT:?}/packages" "${OUT:?}/zapret2"
mkdir -p "$OUT/bin" "$OUT/tree" "$OUT/packages"

# zapret2 (build/deps.json): nfqws2, its Lua libraries and fake payloads
# for the DPI bypass, from the release checked by its SHA-256.
deps="$ROOT/build/deps.json"
zver=$(jq -r .zapret2.version "$deps")
curl -fsSL --retry 10 --retry-delay 15 --retry-all-errors "$(jq -r .zapret2.url "$deps")" -o "$OUT/zapret2.zip"
echo "$(jq -r .zapret2.sha256 "$deps")  $OUT/zapret2.zip" | sha256sum -c -
unzip -q "$OUT/zapret2.zip" -d "$OUT/zapret2"
ZDIR="$OUT/zapret2/zapret2-$zver"

# zarch is zapret2's binary folder of a GOARCH.
zarch() {
	case $1 in
	arm64) echo linux-arm64 ;;
	amd64) echo linux-x86_64 ;;
	mipsle) echo linux-mipsel ;;
	mips) echo linux-mips ;;
	arm) echo linux-arm ;;
	esac
}

tarit() { tar --owner=0 --group=0 --numeric-owner --format=gnu "$@"; }

# zapret installs nfqws2, its Lua and the fakes into a folder.
zapret() {
	local z=$1 goarch=$2
	mkdir -p "$z/lua" "$z/blobs"
	install -m 0755 "$ZDIR/binaries/$(zarch "$goarch")/nfqws2" "$z/nfqws2"
	for f in zapret-lib.lua zapret-antidpi.lua zapret-auto.lua; do
		install -m 0644 "$ZDIR/lua/$f" "$z/lua/$f"
	done
	for f in tls_clienthello_www_google_com.bin quic_initial_www_google_com.bin tls_clienthello_vk_com.bin; do
		install -m 0644 "$ZDIR/files/fake/$f" "$z/blobs/$f"
	done
}

for t in "${TARGETS[@]}"; do
	read -r platform pkg goarch extra archs <<<"$t"
	bin="$OUT/bin/$pkg-$goarch"
	tags=()
	case $pkg in
	hyrouter)
		other=hyrouter-lite
		desc="HyRouter: the LAN routed through Hysteria 2 and VLESS servers by rules for devices and sites, with a web interface"
		;;
	hyrouter-lite)
		tags=(-tags lite)
		other=hyrouter
		desc="HyRouter Lite: the LAN routed through Hysteria 2 servers by rules for devices and sites, for routers with 128-256 MB of memory"
		;;
	hyrouter-keenetic)
		tags=(-tags keenetic)
		other=hyrouter-keenetic-lite
		desc="HyRouter for KeeneticOS: the LAN routed through Hysteria 2 and VLESS servers by rules for devices and sites, with a web interface"
		;;
	hyrouter-keenetic-lite)
		tags=(-tags keenetic,lite)
		other=hyrouter-keenetic
		desc="HyRouter Lite for KeeneticOS: the LAN routed through Hysteria 2 servers by rules for devices and sites, for routers with 128-256 MB of memory"
		;;
	esac
	(
		if [ "$extra" != - ]; then export "${extra%%=*}=${extra#*=}"; fi
		cd "$ROOT"
		CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build "${tags[@]}" -trimpath \
			-ldflags "-s -w -X main.version=$VERSION" -o "$bin" ./cmd/hyrouterd
	)
	for arch in $archs; do
		tree="$OUT/tree/${pkg}_$arch"
		mkdir -p "$tree/control"
		if [ "$platform" = openwrt ]; then
			depends=$DEPENDS_OPENWRT
			mkdir -p "$tree/root/usr/bin" "$tree/root/etc/init.d" "$tree/root/lib/upgrade/keep.d"
			install -m 0755 "$bin" "$tree/root/usr/bin/hyrouterd"
			install -m 0755 "$ROOT/build/openwrt/hyrouter.init" "$tree/root/etc/init.d/hyrouter"
			install -m 0755 "$ROOT/build/openwrt/hyrouter-guard.init" "$tree/root/etc/init.d/hyrouter-guard"
			zapret "$tree/root/usr/share/hyrouter/zapret" "$goarch"
			echo /etc/hyrouter/ >"$tree/root/lib/upgrade/keep.d/hyrouter"
			install -m 0755 "$ROOT/build/openwrt/postinst" "$ROOT/build/openwrt/prerm" "$tree/control/"
		else
			depends=$DEPENDS_KEENETIC
			mkdir -p "$tree/root/opt/sbin" "$tree/root/opt/etc/init.d" "$tree/root/opt/etc/ndm/netfilter.d"
			install -m 0755 "$bin" "$tree/root/opt/sbin/hyrouterd"
			install -m 0755 "$ROOT/build/keenetic/S99hyrouter" "$tree/root/opt/etc/init.d/S99hyrouter"
			install -m 0755 "$ROOT/build/keenetic/50-hyrouter.sh" "$tree/root/opt/etc/ndm/netfilter.d/50-hyrouter.sh"
			zapret "$tree/root/opt/share/hyrouter/zapret" "$goarch"
			install -m 0755 "$ROOT/build/keenetic/postinst" "$ROOT/build/keenetic/prerm" "$tree/control/"
		fi
		size=$(du -sb "$tree/root" | cut -f1)
		cat >"$tree/control/control" <<EOF
Package: $pkg
Version: $VERSION-1
Depends: ${depends// /, }
Conflicts: $other
Source: $URL
SourceName: hyrouter
Section: net
URL: $URL
Architecture: $arch
Installed-Size: $size
Description: $desc
EOF
		if [ "$platform" = openwrt ]; then
			# For build/apk.sh (sourced by /bin/sh).
			cat >"$tree/meta" <<EOF
name='$pkg'
version='$VERSION-r1'
arch='$arch'
description='$desc'
url='$URL'
depends='$depends !$other'
EOF
		fi
		(cd "$tree/control" && tarit -czf ../control.tar.gz ./control ./postinst ./prerm)
		(cd "$tree/root" && tarit -czf ../data.tar.gz .)
		echo 2.0 >"$tree/debian-binary"
		(cd "$tree" && tarit -czf "$OUT/packages/${pkg}_${VERSION}-1_$arch.ipk" ./debian-binary ./data.tar.gz ./control.tar.gz)
		rm "$tree/control.tar.gz" "$tree/data.tar.gz" "$tree/debian-binary"
	done
done
cp "$ROOT/build/apk.sh" "$OUT/apk.sh"
ls -l "$OUT/packages"
