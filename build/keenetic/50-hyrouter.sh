#!/bin/sh
# HyRouter: KeeneticOS rebuilt a table of netfilter and dropped HyRouter's
# chains with it. The firmware runs the scripts of /opt/etc/ndm/netfilter.d
# with $type (iptables or ip6tables) and $table after each rebuild; this
# one loads HyRouter's chains again from the files hyrouterd keeps in
# /tmp/hyrouter/fw (internal/ipt) and puts their jumps back first.
# hyrouterd also checks them every 15 seconds.
# shellcheck disable=SC2154 # type and table come from the firmware

PATH=/opt/sbin:/opt/bin:${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}
case "$type" in
iptables) fam=4 ;;
ip6tables) fam=6 ;;
*) exit 0 ;;
esac
case "$table" in
mangle | nat | filter) ;;
*) exit 0 ;;
esac
dir=/tmp/hyrouter/fw
for kind in guard route; do
	rules="$dir/$kind-$fam-$table.rules"
	[ -f "$rules" ] || continue
	ok=""
	for _ in 1 2 3; do
		if "$type-restore" --noflush <"$rules" 2>/dev/null; then
			ok=1
			break
		fi
		sleep 1
	done
	if [ -z "$ok" ]; then
		logger -t hyrouter "netfilter.d: $type $table not loaded again" 2>/dev/null
		continue
	fi
	while read -r from to; do
		[ -n "$to" ] || continue
		"$type" -w -t "$table" -C "$from" -j "$to" 2>/dev/null ||
			"$type" -w -t "$table" -I "$from" 1 -j "$to"
	done <"$dir/$kind-$fam-$table.hooks"
done
exit 0
