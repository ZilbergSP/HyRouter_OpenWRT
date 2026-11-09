#!/bin/sh
# Makes the .apk of OpenWrt 25.x from the trees build/package.sh left,
# with the apk-tools 3 of an OpenWrt 25.12 container:
#
#   docker run --rm -v "$OUT:/out" openwrt/rootfs:x86-64-25.12.6 /bin/sh /out/apk.sh
#
# The packages are not signed: they are installed with
# "apk add --allow-untrusted", as any package from outside the feeds.
set -eu

for t in /out/tree/*/; do
	t=${t%/}
	# shellcheck disable=SC1091
	. "$t/meta"
	# shellcheck disable=SC2154
	apk mkpkg \
		--info "name:$name" \
		--info "version:$version" \
		--info "arch:$arch" \
		--info "description:$description" \
		--info "url:$url" \
		--info "origin:hyrouter" \
		--info "depends:$depends" \
		--script "post-install:$t/control/postinst" \
		--script "pre-deinstall:$t/control/prerm" \
		--files "$t/root" \
		--output "/out/packages/$name-${version}_$arch.apk"
done
ls -l /out/packages
