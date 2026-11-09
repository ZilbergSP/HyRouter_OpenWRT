// Package build holds what the build pins: deps.json, the third-party
// files hyrouterd downloads and checks by SHA-256.
package build

import _ "embed"

// Deps is deps.json.
//
//go:embed deps.json
var Deps []byte
