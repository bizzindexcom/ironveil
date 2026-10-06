//go:build !windows

// IronVeil Keygen is a Windows application. This stub keeps `go build ./...`
// working on other platforms (the core packages are cross-platform and tested).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "IronVeil Keygen is a Windows application. Build it with GOOS=windows.")
	os.Exit(1)
}
