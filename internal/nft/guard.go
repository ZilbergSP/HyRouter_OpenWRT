package nft

import (
	"fmt"
	"strings"
)

// GuardTable is the table of the kill switch while the router boots
// (docs/ARCHITECTURE.md, «Блокировка при загрузке»): the hyrouter-guard
// service loads it before the network comes up, and it stops everything
// the LAN sends beyond the router until hyrouterd has loaded its own table.
// The router itself (its web interface, DNS, DHCP) stays reachable.
const GuardTable = "hyrouter_guard"

// GuardScript is the guard's table for the LAN interfaces lan.
func GuardScript(lan []string) (string, error) {
	var ifs []string
	for _, n := range lan {
		if !validIface(n) {
			return "", fmt.Errorf("неверное имя интерфейса %q", n)
		}
		ifs = append(ifs, `"`+n+`"`)
	}
	if len(ifs) == 0 {
		return "", fmt.Errorf("нет интерфейсов LAN")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", GuardTable, GuardTable)
	fmt.Fprintf(&b, "table inet %s {\n", GuardTable)
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter - 10; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname { %s } counter reject with icmpx admin-prohibited\n", strings.Join(ifs, ", "))
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}
