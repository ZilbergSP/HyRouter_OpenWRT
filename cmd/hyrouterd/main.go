// Command hyrouterd is HyRouter's daemon on the router: it routes the LAN
// through Hysteria 2 and VLESS servers by rules and serves the web
// interface. See docs/ARCHITECTURE.md.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is set at build time: -ldflags "-X main.version=1.0.0".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("hyrouterd", version)
		return
	}
	fmt.Fprintln(os.Stderr, "hyrouterd: маршрутизация ещё не готова")
	os.Exit(2)
}
