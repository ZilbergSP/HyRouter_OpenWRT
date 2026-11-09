// Package webui embeds the built web interface (web/dist, committed) in
// hyrouterd.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var files embed.FS

// Dist is the built interface: index.html and its assets.
func Dist() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
