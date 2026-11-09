#!/usr/bin/env bash
# Integration test in network namespaces (docs/ARCHITECTURE.md, «Тесты»):
# two devices → a router with hyrouterd, nftables and TPROXY → an
# "internet" with a real Hysteria 2 server and HTTP and UDP servers that
# answer with the address they see. Direct traffic arrives from the
# router's WAN address, tunnel traffic from the Hysteria server.
#
# Root only, in CI only: never on a maintainer's PC (it builds bridges and
# routes, and a mistake would cut the machine's network).
#
#   sudo test/netns.sh HYROUTERD HYSTERIA HYSTERIA_VERSION
#
# With HYROUTER_EMBEDDED=1 (HyRouter Lite) the router gets no hysteria
# binary: its client runs inside hyrouterd, and HYSTERIA is the server only.
#
# With HYROUTER_PLATFORM=keenetic (a build with -tags keenetic) the router
# is a KeeneticOS one: iptables and ipset (legacy, as Entware's) instead of
# nftables, the firmware's DNS on the LAN address, and the firmware's
# rebuilds of its tables, which the netfilter.d hook and hyrouterd undo.
set -euo pipefail

HYROUTERD=$1
HYSTERIA=$2
HYVERSION=$3
WAN=198.51.100.1
W=$(mktemp -d)
PIDS=()
HERE=$(cd "$(dirname "$0")" && pwd)
KEENETIC=""
CORES=/usr/share/hyrouter/bin
MARK=0x8000000
if [ "${HYROUTER_PLATFORM:-}" = keenetic ]; then
	KEENETIC=1
	CORES=/opt/share/hyrouter/bin
	MARK=0x80000000
	# Entware's iptables is the legacy one.
	mkdir -p "$W/bin"
	for t in iptables ip6tables; do
		for s in "" -save -restore; do
			ln -s "$(command -v "$t-legacy$s")" "$W/bin/$t$s"
		done
	done
	export PATH="$W/bin:$PATH"
fi

dump() {
	echo "=== hyrouterd"
	cat "$W/hyrouterd.log" 2>/dev/null || true
	echo "=== hysteria server"
	tail -n 30 "$W/hysteria-server.log" 2>/dev/null || true
	if [ -n "$KEENETIC" ]; then
		echo "=== iptables of the router"
		ip netns exec rtr iptables-save 2>/dev/null | head -n 200 || true
		echo "=== ipsets"
		ip netns exec rtr ipset list -n 2>/dev/null || true
	else
		echo "=== nftables of the router"
		ip netns exec rtr nft list ruleset 2>/dev/null | head -n 200 || true
	fi
	echo "=== ip rule"
	ip netns exec rtr ip rule 2>/dev/null || true
}

cleanup() {
	# By PID: this script's own command line names hyrouterd too.
	if [ -n "${HYR:-}" ]; then kill "$HYR" 2>/dev/null || true; fi
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	for ns in dev dev2 rtr net; do ip netns del "$ns" 2>/dev/null || true; done
	rm -rf /etc/netns/dev /etc/netns/dev2
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*"
	dump
	exit 1
}

pass() { echo "ok: $*"; }

modprobe -a nft_tproxy nf_tproxy_ipv4 nf_tproxy_ipv6 nft_socket nft_fib_inet nft_reject_inet nft_redir nft_nat 2>/dev/null || true
if [ -n "$KEENETIC" ]; then
	modprobe -a xt_TPROXY ip_set ip_set_hash_ip ip_set_hash_net xt_set xt_connmark xt_mark xt_mac xt_multiport xt_addrtype xt_conntrack \
		iptable_mangle iptable_nat iptable_filter ip6table_mangle ip6table_nat ip6table_filter xt_REDIRECT ipt_REJECT ip6t_REJECT 2>/dev/null || true
fi

# --- the network ---------------------------------------------------------
for ns in dev dev2 rtr net; do
	ip netns add "$ns"
	ip -n "$ns" link set lo up
done
ip -n rtr link add br-lan type bridge
ip -n rtr link set br-lan up
ip -n rtr addr add 192.168.50.1/24 dev br-lan
n=2
for d in dev dev2; do
	ip link add "$d-eth" netns "$d" type veth peer name "$d-port" netns rtr
	ip -n rtr link set "$d-port" master br-lan up
	ip -n "$d" link set "$d-eth" up
	ip -n "$d" addr add "192.168.50.$n/24" dev "$d-eth"
	ip -n "$d" route add default via 192.168.50.1
	mkdir -p "/etc/netns/$d"
	echo "nameserver 192.168.50.1" >"/etc/netns/$d/resolv.conf"
	n=$((n + 1))
done
ip link add rtr-wan netns rtr type veth peer name net-eth netns net
ip -n rtr addr add "$WAN/24" dev rtr-wan
ip -n rtr link set rtr-wan up
ip -n rtr route add default via 198.51.100.2
ip -n net addr add 198.51.100.2/24 dev net-eth
ip -n net link set net-eth up
for a in 10 20 30 40 50; do ip -n net addr add "203.0.113.$a/32" dev lo; done
ip netns exec rtr sysctl -qw net.ipv4.ip_forward=1
ip netns exec rtr nft -f - <<'EOF'
table ip ci_nat {
	chain post {
		type nat hook postrouting priority 100; policy accept;
		oifname "rtr-wan" masquerade
	}
}
EOF

# --- the internet --------------------------------------------------------
cat >"$W/web.py" <<'EOF'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (self.client_address[0] + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", 80), H).serve_forever()
EOF
# One socket per address: a reply must come from the address the client
# asked, or the router's conntrack does not take it for the answer.
cat >"$W/udp.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 5353))
while True:
    data, addr = s.recvfrom(2048)
    s.sendto(addr[0].encode(), addr)
EOF
cat >"$W/udpc.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b"ping", (sys.argv[1], 5353))
try:
    print(s.recvfrom(2048)[0].decode())
except Exception:
    print("ERR")
EOF
ip netns exec net python3 "$W/web.py" &
PIDS+=($!)
for a in 10 20 30 40 50; do
	ip netns exec net python3 "$W/udp.py" "203.0.113.$a" &
	PIDS+=($!)
done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/key.pem" -out "$W/cert.pem" -days 1 -subj /CN=ci.test 2>/dev/null
cat >"$W/server.yaml" <<EOF
listen: 198.51.100.2:8443
tls:
  cert: $W/cert.pem
  key: $W/key.pem
auth:
  type: password
  password: ci-pass
EOF
start_server() {
	ip netns exec net "$HYSTERIA" server -c "$W/server.yaml" >>"$W/hysteria-server.log" 2>&1 &
	SERVER=$!
	PIDS+=("$SERVER")
}
start_server

# --- the router ----------------------------------------------------------
# dnsmasq is OpenWrt's DNS on loopback; KeeneticOS's DNS answers on the
# LAN address too.
listen=(--listen-address=127.0.0.1)
if [ -n "$KEENETIC" ]; then
	listen+=(--listen-address=192.168.50.1)
fi
ip netns exec rtr dnsmasq --keep-in-foreground --no-resolv --no-hosts --bind-interfaces \
	"${listen[@]}" --port=53 --pid-file="$W/dnsmasq.pid" \
	--address=/vpn.test/203.0.113.30 --address=/a.test/203.0.113.40 --address=/b.test/203.0.113.40 &
PIDS+=($!)
mkdir -p "$W/etc" "$CORES"
rm -f "$CORES"/hysteria-*
if [ "${HYROUTER_EMBEDDED:-0}" != 1 ]; then
	install -m 0755 "$HYSTERIA" "$CORES/hysteria-${HYVERSION//\//-}"
fi
cat >"$W/etc/settings.json" <<'EOF'
{"enabled": true, "lan": ["br-lan"], "main": "srv-ci", "dns": {"byRules": false}}
EOF
cat >"$W/etc/servers.json" <<'EOF'
[{"id": "srv-ci", "name": "ci", "host": "198.51.100.2", "ports": "8443", "auth": "ci-pass", "tls": {"sni": "ci.test", "insecure": true}}]
EOF
cat >"$W/etc/rules.json" <<'EOF'
{"defaultAction": "direct", "rules": [
	{"name": "dev2 через VPN", "devices": ["192.168.50.3"], "action": "tunnel"},
	{"name": "адрес через VPN", "domains": ["203.0.113.20"], "action": "tunnel"},
	{"name": "блок", "domains": ["203.0.113.50"], "action": "block"},
	{"name": "сайты через VPN", "domains": ["vpn.test", "a.test"], "action": "tunnel"},
	{"name": "сайт напрямую", "domains": ["b.test"], "action": "direct"}
]}
EOF
start_hyrouterd() {
	ip netns exec rtr "$HYROUTERD" -config "$W/etc" >>"$W/hyrouterd.log" 2>&1 &
	HYR=$!
}
start_hyrouterd

seen() { ip netns exec "$1" curl -s --max-time 8 "${@:2}" || echo ERR; }
udp() { ip netns exec "$1" python3 "$W/udpc.py" "$2"; }
direct() {
	local got
	got=$(seen "$@")
	[ "$got" = "$WAN" ] || fail "$*: expected direct, the server saw '$got'"
	pass "$* direct"
}
tunnel() {
	local got
	got=$(seen "$@")
	[ "$got" != "$WAN" ] && [ "$got" != ERR ] || fail "$*: expected the tunnel, the server saw '$got'"
	pass "$* through the tunnel ($got)"
}
refused() {
	local got
	got=$(seen "$@")
	[ "$got" = ERR ] || fail "$*: expected a refusal, the server saw '$got'"
	pass "$* refused"
}

# Routing is up once the tunnel carries a connection.
up=""
for _ in $(seq 1 40); do
	got=$(seen dev http://203.0.113.20/)
	if [ "$got" != ERR ] && [ "$got" != "$WAN" ]; then
		up=1
		break
	fi
	sleep 1
done
[ -n "$up" ] || fail "the tunnel never came up"

direct dev http://203.0.113.10/
tunnel dev http://203.0.113.20/
refused dev http://203.0.113.50/
tunnel dev2 http://203.0.113.10/
tunnel dev http://vpn.test/
tunnel dev http://a.test/
direct dev http://b.test/

got=$(udp dev 203.0.113.20)
[ "$got" != ERR ] && [ "$got" != "$WAN" ] || fail "UDP to 203.0.113.20: expected the tunnel, got '$got'"
pass "UDP through the tunnel ($got)"
got=$(udp dev 203.0.113.10)
[ "$got" = "$WAN" ] || fail "UDP to 203.0.113.10: expected direct, got '$got'"
pass "UDP direct"
got=$(udp dev 203.0.113.50)
[ "$got" = ERR ] || fail "UDP to 203.0.113.50: expected a block, got '$got'"
pass "UDP blocked"

# The server goes away: tunnel traffic is refused, never sent direct.
kill "$SERVER"
wait "$SERVER" 2>/dev/null || true
refused dev http://203.0.113.20/
direct dev http://203.0.113.10/
start_server

# hyrouterd crashes: its table stays, tunnel traffic finds no relay and is
# refused, direct traffic goes on in the kernel.
kill -9 "$HYR"
wait "$HYR" 2>/dev/null || true
refused dev http://203.0.113.20/
direct dev http://203.0.113.10/

# It comes back (procd) and routes again.
start_hyrouterd
wait_tunnel() {
	local i
	for i in $(seq 1 "$1"); do
		got=$(seen dev http://203.0.113.20/)
		if [ "$got" != ERR ] && [ "$got" != "$WAN" ]; then
			return 0
		fi
		[ "$i" = "$1" ] || sleep 1
	done
	return 1
}
wait_tunnel 40 || fail "routing did not come back after a restart"
pass "routing back after a crash"

if [ -n "$KEENETIC" ]; then
	# Every table of both families loaded: no fallback warnings.
	if grep -E "IPv6 (DNS|connections)|IPv6 устройств|правила IPv6" "$W/hyrouterd.log"; then
		fail "the IPv6 rules did not load"
	fi
	# The firmware rebuilds the mangle table and drops HyRouter's chains;
	# its netfilter.d hook loads them again from hyrouterd's files.
	ip netns exec rtr iptables -t mangle -F
	ip netns exec rtr iptables -t mangle -X
	ip netns exec rtr env type=iptables table=mangle sh "$HERE/../build/keenetic/50-hyrouter.sh"
	tunnel dev http://203.0.113.20/
	direct dev http://203.0.113.10/
	pass "the netfilter.d hook put the rules back"

	# A rebuild without the hook (it failed on some firmware): hyrouterd
	# puts them back itself.
	ip netns exec rtr iptables -t mangle -F
	ip netns exec rtr iptables -t mangle -X
	wait_tunnel 40 || fail "hyrouterd did not put the rules back"
	pass "hyrouterd put the rules back"

	# The firmware takes the routing rule: VPN traffic is refused, never
	# sent direct, until hyrouterd adds it again.
	ip netns exec rtr ip rule del fwmark "$MARK/$MARK" lookup 7701
	refused dev http://203.0.113.20/
	wait_tunnel 40 || fail "hyrouterd did not add the routing rule again"
	pass "the routing rule back"
fi

# A stop removes everything: the LAN goes as without HyRouter.
kill -TERM "$HYR"
wait "$HYR" 2>/dev/null || true
if [ -n "$KEENETIC" ]; then
	if ip netns exec rtr iptables-save | grep -q HYR_; then
		fail "HyRouter's chains are still there after a stop"
	fi
	if ip netns exec rtr ipset list -n | grep -q '^hyr_'; then
		fail "HyRouter's ipsets are still there after a stop"
	fi
elif ip netns exec rtr nft list table inet hyrouter >/dev/null 2>&1; then
	fail "the table is still there after a stop"
fi
if ip netns exec rtr ip rule | grep -q "$MARK"; then
	fail "the policy routing rule is still there after a stop"
fi
direct dev http://203.0.113.20/
pass "stop removed the table and the rules"
echo "all passed"
