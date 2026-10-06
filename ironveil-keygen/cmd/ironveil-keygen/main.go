//go:build windows

// IronVeil Keygen: offline Windows tool that issues IronVeil Security license keys.
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "1.0.0"

func main() {
	// Every Win32 window call must come from the thread that created the window.
	runtime.LockOSThread()
	hardenProcess()
	defer func() {
		if r := recover(); r != nil {
			if theApp != nil {
				theApp.lock(false) // Wipe the key before exiting.
			}
			messageBox(0, fmt.Sprintf("IronVeil Keygen stopped because of an unexpected error:\n\n%v\n\n%s", r, firstLines(string(debug.Stack()), 12)), appTitle, mbOK|mbIconError)
			os.Exit(2)
		}
	}()
	if err := run(); err != nil {
		messageBox(0, "IronVeil Keygen could not start: "+err.Error(), appTitle, mbOK|mbIconError)
		os.Exit(1)
	}
}

func firstLines(s string, n int) string {
	lines := 0
	for i, c := range s {
		if c == '\n' {
			lines++
			if lines == n {
				return s[:i]
			}
		}
	}
	return s
}
