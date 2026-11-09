//go:build linux

package ipt

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// modules are the kernel modules the rules need. KeeneticOS ships them
// with the component «Модули ядра подсистемы Netfilter» but does not
// always load them on demand (nfqws-keenetic loads its own too). A name
// the kernel does not have is skipped: iptables then names what is
// missing.
var modules = []string{
	"x_tables", "ip_tables", "ip6_tables", "nf_conntrack", "nf_defrag_ipv4", "nf_defrag_ipv6",
	"iptable_mangle", "ip6table_mangle", "iptable_filter", "ip6table_filter",
	"nf_nat", "nf_nat_ipv4", "nf_nat_ipv6", "iptable_nat", "ip6table_nat",
	"xt_conntrack", "xt_connmark", "xt_mark", "xt_mac", "xt_multiport", "xt_addrtype", "xt_connbytes", "xt_comment",
	"nf_tproxy_core", "nf_tproxy_ipv4", "nf_tproxy_ipv6", "xt_TPROXY",
	"ip_set", "ip_set_hash_ip", "ip_set_hash_net", "xt_set",
	"nf_reject_ipv4", "nf_reject_ipv6", "ipt_REJECT", "ip6t_REJECT", "xt_REJECT",
	"nf_nat_redirect", "xt_REDIRECT", "ipt_REDIRECT", "ip6t_REDIRECT", "nf_nat_masquerade_ipv4", "ipt_MASQUERADE", "xt_MASQUERADE",
	"nfnetlink", "nfnetlink_queue", "xt_NFQUEUE",
}

var modOnce sync.Once

// loadModules loads the modules that are not yet, from the plain .ko
// files of /lib/modules/<release> (a module that needs another loads in a
// later pass). Kernels whose modules are compressed load them on demand.
func loadModules() {
	modOnce.Do(func() {
		var u unix.Utsname
		if unix.Uname(&u) != nil {
			return
		}
		dir := filepath.Join("/lib/modules", unix.ByteSliceToString(u.Release[:]))
		files := map[string]string{}
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".ko") {
				return nil
			}
			name := strings.ReplaceAll(strings.TrimSuffix(d.Name(), ".ko"), "-", "_")
			files[name] = path
			return nil
		})
		if len(files) == 0 {
			return
		}
		loaded := loadedModules()
		var todo []string
		for _, m := range modules {
			if _, ok := files[m]; ok && !loaded[m] {
				todo = append(todo, m)
			}
		}
		for len(todo) > 0 {
			var left []string
			for _, m := range todo {
				if err := insmod(files[m]); err != nil && !errors.Is(err, unix.EEXIST) {
					left = append(left, m)
				}
			}
			if len(left) == len(todo) {
				return // no progress: the rest needs what the kernel lacks
			}
			todo = left
		}
	})
}

// loadedModules reads /proc/modules.
func loadedModules() map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			out[f[0]] = true
		}
	}
	return out
}

func insmod(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return unix.FinitModule(int(f.Fd()), "", 0)
}
