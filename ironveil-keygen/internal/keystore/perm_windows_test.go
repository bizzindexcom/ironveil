//go:build windows

package keystore

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS ("FA" in SDDL).
const fileAllAccess = 0x1F01FF

// checkOwnerOnly asserts that sd has a protected DACL with exactly one ACE:
// an allow ACE with full access for the current user.
func checkOwnerOnly(t *testing.T, what string, sd *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s: DACL is not protected from inheritance (%s)", what, sd)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no DACL: %v", what, err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("%s: want exactly 1 ACE, got %d (%s)", what, dacl.AceCount, sd)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("%s: ACE is not an allow ACE", what)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.Equals(user.User.Sid) {
		t.Fatalf("%s: ACE grants %s, want the current user %s", what, sid, user.User.Sid)
	}
	if ace.Mask&fileAllAccess != fileAllAccess {
		t.Fatalf("%s: ACE mask %#x lacks full access", what, ace.Mask)
	}
}

func TestOwnerOnlySecurityDescriptor(t *testing.T) {
	sd, err := ownerOnlySD()
	if err != nil {
		t.Fatal(err)
	}
	checkOwnerOnly(t, "ownerOnlySD", sd)
}

// underWine reports whether the test runs under Wine, which accepts but does
// not persist file DACLs, so the on-disk read-back cannot be checked there.
func underWine() bool {
	return windows.NewLazySystemDLL("ntdll.dll").NewProc("wine_get_version").Find() == nil
}

func TestWindowsOwnerOnlyACLOnDisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k"+FileExt)
	if err := WriteFileSecure(p, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RestrictDir(sub); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "issued.jsonl")
	if err := os.WriteFile(f, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestrictFile(f); err != nil {
		t.Fatal(err)
	}
	if underWine() {
		t.Skip("Wine does not persist file DACLs; run on Windows to check the on-disk ACLs")
	}
	for _, path := range []string{p, sub, f} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		checkOwnerOnly(t, path, sd)
	}
}
