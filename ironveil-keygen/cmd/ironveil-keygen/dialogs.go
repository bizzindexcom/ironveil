//go:build windows

package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/bizzindexcom/ironveil/ironveil-keygen/internal/keystore"
)

// ---------------------------------------------------------------- Passphrase dialog.

const (
	idPassEdit1 = 101
	idPassEdit2 = 102
	dlgClass    = "IronVeilKeygenPassphrase"
)

type passDialog struct {
	hwnd, owner      uintptr
	edit1, edit2     uintptr
	confirm          bool
	done             bool
	result           []byte
	ownerWasDisabled bool
}

var (
	activeDlg     *passDialog
	dlgRegistered bool
	dlgProcPtr    = windows.NewCallback(dlgProc)
)

// askPassphrase shows a modal passphrase prompt. In confirm mode the user
// types it twice and the keystore policy is enforced. The caller must wipe
// the returned bytes.
func askPassphrase(a *app, title, prompt string, confirm bool) ([]byte, bool) {
	if activeDlg != nil {
		return nil, false
	}
	if !dlgRegistered {
		wc := wndClassEx{
			Size:       uint32(unsafe.Sizeof(wndClassEx{})),
			WndProc:    dlgProcPtr,
			Instance:   a.inst,
			Cursor:     loadCursor(idcArrow),
			Background: sysColorBrush(colorBtnFace),
			ClassName:  u16(dlgClass),
			Icon:       a.icon,
			IconSm:     a.icon,
		}
		if r, _, _ := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			return nil, false
		}
		dlgRegistered = true
	}
	d := &passDialog{owner: a.hwnd, confirm: confirm}
	activeDlg = d
	defer func() { activeDlg = nil }()

	s := a.scale
	w, h := s(420), s(190)
	if confirm {
		h = s(270)
	}
	var or rect
	_, _, _ = pGetClientRect.Call(a.hwnd, uintptr(unsafe.Pointer(&or)))
	x, y := centerOver(a.hwnd, w, h)
	d.hwnd = createWindow(wsExDlgModalFrame|wsExControlParent, dlgClass, title, wsPopup|wsCaption|wsSysMenu|wsDlgFrame, x, y, w, h, a.hwnd, 0, a.inst)
	if d.hwnd == 0 {
		return nil, false
	}
	pad := s(16)
	cw := w - 2*pad - s(8)
	yy := pad
	lbl := a.child(d.hwnd, "STATIC", prompt, 0, pad, yy, cw, s(48), 0)
	_ = lbl
	yy += s(54)
	d.edit1 = a.child(d.hwnd, "EDIT", "", wsTabStop|esPassword|esAutoHScroll, pad, yy, cw, s(26), idPassEdit1)
	sendMessage(d.edit1, emLimitText, 1024, 0)
	yy += s(34)
	if confirm {
		a.child(d.hwnd, "STATIC", "Type it again:", 0, pad, yy, cw, s(20), 0)
		yy += s(22)
		d.edit2 = a.child(d.hwnd, "EDIT", "", wsTabStop|esPassword|esAutoHScroll, pad, yy, cw, s(26), idPassEdit2)
		sendMessage(d.edit2, emLimitText, 1024, 0)
		yy += s(34)
	}
	bw := s(96)
	a.child(d.hwnd, "BUTTON", "OK", wsTabStop|bsDefPushButton, w-pad-2*bw-s(18), yy+s(4), bw, s(30), idOK)
	a.child(d.hwnd, "BUTTON", "Cancel", wsTabStop|bsPushButton, w-pad-bw-s(10), yy+s(4), bw, s(30), idCancel)

	d.ownerWasDisabled = !isEnabled(a.hwnd)
	enable(a.hwnd, false)
	_, _, _ = pShowWindow.Call(d.hwnd, swShow)
	_, _, _ = pSetFocus.Call(d.edit1)

	var m msg
	for !d.done {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			postMessage(0, 0x0012, 0, 0) // Re-post WM_QUIT for the outer loop.
			d.done = true
			break
		}
		if ok, _, _ := pIsDialogMessageW.Call(d.hwnd, uintptr(unsafe.Pointer(&m))); ok != 0 {
			continue
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	if !d.ownerWasDisabled {
		enable(a.hwnd, true)
	}
	_, _, _ = pDestroyWindow.Call(d.hwnd)
	_, _, _ = pSetForegroundWindow.Call(a.hwnd)
	return d.result, d.result != nil
}

func dlgProc(hwnd, m, wp, lp uintptr) uintptr {
	d := activeDlg
	if d == nil || hwnd != d.hwnd {
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	switch uint32(m) {
	case wmCommand:
		switch wp & 0xFFFF {
		case idOK:
			d.submit()
			return 0
		case idCancel:
			d.clear()
			d.done = true
			return 0
		}
	case wmClose:
		d.clear()
		d.done = true
		return 0
	case wmCtlColorStatic:
		_, _, _ = pSetBkMode.Call(wp, transparent)
		return sysColorBrush(colorBtnFace)
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

func (d *passDialog) clear() {
	setText(d.edit1, "")
	if d.edit2 != 0 {
		setText(d.edit2, "")
	}
}

func (d *passDialog) submit() {
	b1 := getTextUTF16(d.edit1)
	p1 := utf16ToUTF8(b1)
	wipe16(b1)
	if d.confirm {
		b2 := getTextUTF16(d.edit2)
		p2 := utf16ToUTF8(b2)
		wipe16(b2)
		same := subtle.ConstantTimeCompare(p1, p2) == 1
		keystore.Wipe(p2)
		if !same {
			keystore.Wipe(p1)
			d.retry("The two passphrases do not match. Type the passphrase again in both fields.")
			return
		}
		if err := keystore.CheckPassphrase(p1); err != nil {
			keystore.Wipe(p1)
			d.retry(capitalize(err.Error()) + ".")
			return
		}
	} else if len(p1) == 0 {
		_, _, _ = pSetFocus.Call(d.edit1)
		return
	}
	d.clear()
	d.result = p1
	d.done = true
}

// retry explains the problem, clears both fields and puts the caret back in
// the first one, so a retry never mixes old and new input.
func (d *passDialog) retry(text string) {
	d.clear()
	messageBox(d.hwnd, text, "IronVeil Keygen", mbOK|mbIconWarning)
	_, _, _ = pSetFocus.Call(d.edit1)
}

func wipe16(b []uint16) {

	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------- File dialogs.

// filterUTF16 builds "Label\0pattern\0…\0\0".
func filterUTF16(pairs ...string) *uint16 {
	var out []uint16
	for _, p := range pairs {
		out = append(out, utf16.Encode([]rune(p))...)
		out = append(out, 0)
	}
	out = append(out, 0)
	return &out[0]
}

func fileDialog(owner uintptr, save bool, title string, filter *uint16, defExt, defName, initialDir string) (string, bool) {
	buf := make([]uint16, 32768)
	copy(buf, utf16.Encode([]rune(defName)))
	ofn := openFileName{
		StructSize: uint32(unsafe.Sizeof(openFileName{})),
		Owner:      owner,
		Filter:     filter,
		File:       &buf[0],
		MaxFile:    uint32(len(buf)),
		Title:      u16(title),
		Flags:      ofnExplorer | ofnNoChangeDir | ofnHideReadOnly | ofnPathMustExist | ofnDontAddToRecent,
	}
	if initialDir != "" {
		ofn.InitialDir = u16(initialDir)
	}
	if defExt != "" {
		ofn.DefExt = u16(defExt)
	}
	proc := pGetOpenFileNameW
	if save {
		proc = pGetSaveFileNameW
		ofn.Flags |= ofnOverwritePrompt
	} else {
		ofn.Flags |= ofnFileMustExist
	}
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		// Zero means cancelled unless the dialog reports an error.
		if code, _, _ := pCommDlgExtendedError.Call(); code != 0 {
			messageBox(owner, fmt.Sprintf("The file dialog could not be shown (error 0x%X).", code), appTitle, mbOK|mbIconError)
		}
		return "", false
	}
	return windows.UTF16ToString(buf), true
}

// ---------------------------------------------------------------- Clipboard.

// copyToClipboard places text on the clipboard and asks Windows not to keep
// it in clipboard history or sync it to the cloud.
func copyToClipboard(owner uintptr, text string) error {
	data := utf16.Encode([]rune(text))
	data = append(data, 0)
	size := uintptr(len(data) * 2)
	var opened bool
	for i := 0; i < 5 && !opened; i++ { // Another app may hold the clipboard briefly.
		r, _, _ := pOpenClipboard.Call(owner)
		opened = r != 0
		if !opened {
			windows.SleepEx(30, false)
		}
	}
	if !opened {
		return errors.New("the clipboard is busy; try again")
	}
	defer pCloseClipboard.Call()
	_, _, _ = pEmptyClipboard.Call()
	if err := setClipboardBytes(cfUnicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), size)); err != nil {
		return err
	}
	zero := []byte{0, 0, 0, 0}
	for _, name := range []string{"CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"} {
		if f, _, _ := pRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(u16(name)))); f != 0 {
			_ = setClipboardBytes(uint32(f), zero)
		}
	}
	if f, _, _ := pRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(u16("ExcludeClipboardContentFromMonitorProcessing")))); f != 0 {
		_ = setClipboardBytes(uint32(f), zero[:1])
	}
	return nil
}

func setClipboardBytes(format uint32, b []byte) error {
	h, _, _ := pGlobalAlloc.Call(gmemMoveable, uintptr(len(b)))
	if h == 0 {
		return errors.New("out of memory")
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		_, _, _ = pGlobalFree.Call(h)
		return errors.New("could not lock clipboard memory")
	}
	copy(unsafe.Slice((*byte)(winPtr(p)), len(b)), b) // Win32 global memory of exactly len(b) bytes.
	_, _, _ = pGlobalUnlock.Call(h)
	if r, _, _ := pSetClipboardData.Call(uintptr(format), h); r == 0 {
		_, _, _ = pGlobalFree.Call(h) // Ownership passes to the system only on success.
		return errors.New("could not set clipboard data")
	}
	return nil
}

// openFolder shows a folder in Explorer.
func openFolder(path string) {
	_, _, _ = pShellExecuteW.Call(0, uintptr(unsafe.Pointer(u16("open"))), uintptr(unsafe.Pointer(u16(path))), 0, 0, swShowNormal)
}

// ---------------------------------------------------------------- Small helpers.

func createWindow(ex uint32, class, title string, style uint32, x, y, w, h int32, parent, id, inst uintptr) uintptr {
	r, _, _ := pCreateWindowExW.Call(uintptr(ex), uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(title))), uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, id, inst, 0)
	return r
}

func loadCursor(id uintptr) uintptr {
	r, _, _ := pLoadCursorW.Call(0, id)
	return r
}

func sysColorBrush(idx uintptr) uintptr {
	r, _, _ := pGetSysColorBrush.Call(idx)
	return r
}

func isEnabled(h uintptr) bool {
	r, _, _ := pIsWindowEnabled.Call(h)
	return r != 0
}

func centerOver(owner uintptr, w, h int32) (int32, int32) {
	var r rect
	getWindowRect(owner, &r)
	x := r.Left + (r.Right-r.Left-w)/2
	y := r.Top + (r.Bottom-r.Top-h)/2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	return x, y
}

var pGetWindowRect = user32.NewProc("GetWindowRect")

func getWindowRect(h uintptr, r *rect) {
	_, _, _ = pGetWindowRect.Call(h, uintptr(unsafe.Pointer(r)))
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 32
	}
	return string(r)
}
