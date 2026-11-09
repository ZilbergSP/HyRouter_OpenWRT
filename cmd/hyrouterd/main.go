// Command hyrouterd is HyRouter's daemon on the router: it routes the LAN
// through Hysteria 2 and VLESS servers by rules and serves the web
// interface. See docs/ARCHITECTURE.md.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/zilbergsp/hyrouter/internal/edition"
	"github.com/zilbergsp/hyrouter/internal/platform"
)

// version is set at build time: -ldflags "-X main.version=1.0.0".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	dir := flag.String("config", platform.ConfigDir, "the settings folder")
	clean := flag.Bool("cleanup", false, "remove HyRouter's firewall rules, its kill switch and routing rule, and exit (the package's removal)")
	update := flag.Bool("update", false, "install the newest HyRouter release for this router (the package manager restarts the service) and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("hyrouterd %s (%s, %s)\n", version, edition.Name, platform.Name)
		return
	}
	platform.Init()
	if *clean {
		os.Exit(cleanup())
	}
	if *update {
		os.Exit(selfUpdate())
	}
	os.Exit(run(*dir))
}
