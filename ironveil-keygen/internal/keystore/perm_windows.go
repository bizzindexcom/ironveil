//go:build windows

package keystore

import (
	"golang.org/x/sys/windows"
)

// restrictFile replaces the file's ACL with a protected one that grants full
// access to the current user only (no inherited ACEs, no Everyone/Users).
func restrictFile(path string) error {
	return restrictPath(path)
}

// ownerOnlySD builds a security descriptor with a protected DACL holding a
// single ACE: full access for the current user, inherited by children.
func ownerOnlySD() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
}

// restrictPath also works for directories (the app-data folder).
func restrictPath(path string) error {
	sd, err := ownerOnlySD()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// RestrictDir locks a folder to the current user.
func RestrictDir(path string) error { return restrictPath(path) }
