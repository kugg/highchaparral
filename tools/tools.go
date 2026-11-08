//go:build tools

// Package tools pins CI-only build tools so their versions are tracked in
// go.mod and kept current by Dependabot (gomod ecosystem), instead of a
// bare `go install ...@latest` that can silently drift to an unmaintained
// version. This file is excluded from normal builds by the `tools` tag.
package tools

import _ "golang.org/x/vuln/cmd/govulncheck"
