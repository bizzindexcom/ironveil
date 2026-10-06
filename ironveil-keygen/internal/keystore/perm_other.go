//go:build !windows

package keystore

import "os"

func restrictFile(path string) error { return os.Chmod(path, 0o600) }

// RestrictDir locks a folder to the current user.
func RestrictDir(path string) error { return os.Chmod(path, 0o700) }
