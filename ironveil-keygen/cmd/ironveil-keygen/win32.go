//go:build windows

package main

// Minimal, audited Win32 bindings (user32, gdi32, comctl32, comdlg32,
// kernel32, wtsapi32) on top of golang.org/x/sys/windows. Only system DLLs
// are loaded, always from System32.

import (
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	comctl32 = windows.NewLazySystemDLL("comctl32.dll")
	comdlg32 = windows.NewLazySystemDLL("comdlg32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	wtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")

	pRegisterClassExW           = user32.NewProc("RegisterClassExW")
	pCreateWindowExW            = user32.NewProc("CreateWindowExW")
	pDefWindowProcW             = user32.NewProc("DefWindowProcW")
	pDestroyWindow              = user32.NewProc("DestroyWindow")
	pGetMessageW                = user32.NewProc("GetMessageW")
	pTranslateMessage           = user32.NewProc("TranslateMessage")
	pDispatchMessageW           = user32.NewProc("DispatchMessageW")
	pIsDialogMessageW           = user32.NewProc("IsDialogMessageW")
	pPostQuitMessage            = user32.NewProc("PostQuitMessage")
	pPostMessageW               = user32.NewProc("PostMessageW")
	pSendMessageW               = user32.NewProc("SendMessageW")
	pShowWindow                 = user32.NewProc("ShowWindow")
	pUpdateWindow               = user32.NewProc("UpdateWindow")
	pMessageBoxW                = user32.NewProc("MessageBoxW")
	pSetWindowTextW             = user32.NewProc("SetWindowTextW")
	pGetWindowTextW             = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW       = user32.NewProc("GetWindowTextLengthW")
	pEnableWindow               = user32.NewProc("EnableWindow")
	pSetWindowPos               = user32.NewProc("SetWindowPos")
	pSetFocus                   = user32.NewProc("SetFocus")
	pLoadCursorW                = user32.NewProc("LoadCursorW")
	pLoadIconW                  = user32.NewProc("LoadIconW")
	pSetCursor                  = user32.NewProc("SetCursor")
	pGetClientRect              = user32.NewProc("GetClientRect")
	pGetDpiForWindow            = user32.NewProc("GetDpiForWindow")
	pSetProcessDpiAwarenessCtx  = user32.NewProc("SetProcessDpiAwarenessContext")
	pAdjustWindowRectEx         = user32.NewProc("AdjustWindowRectEx")
	pSetTimer                   = user32.NewProc("SetTimer")
	pKillTimer                  = user32.NewProc("KillTimer")
	pGetLastInputInfo           = user32.NewProc("GetLastInputInfo")
	pOpenClipboard              = user32.NewProc("OpenClipboard")
	pCloseClipboard             = user32.NewProc("CloseClipboard")
	pEmptyClipboard             = user32.NewProc("EmptyClipboard")
	pSetClipboardData           = user32.NewProc("SetClipboardData")
	pRegisterClipboardFormatW   = user32.NewProc("RegisterClipboardFormatW")
	pGetSystemMetrics           = user32.NewProc("GetSystemMetrics")
	pIsWindowEnabled            = user32.NewProc("IsWindowEnabled")
	pSetForegroundWindow        = user32.NewProc("SetForegroundWindow")
	pGetSysColorBrush           = user32.NewProc("GetSysColorBrush")
	pCreateFontW                = gdi32.NewProc("CreateFontW")
	pDeleteObject               = gdi32.NewProc("DeleteObject")
	pSetBkMode                  = gdi32.NewProc("SetBkMode")
	pInitCommonControlsEx       = comctl32.NewProc("InitCommonControlsEx")
	pGetOpenFileNameW           = comdlg32.NewProc("GetOpenFileNameW")
	pGetSaveFileNameW           = comdlg32.NewProc("GetSaveFileNameW")
	pCommDlgExtendedError       = comdlg32.NewProc("CommDlgExtendedError")
	pGetModuleHandleW           = kernel32.NewProc("GetModuleHandleW")
	pGlobalAlloc                = kernel32.NewProc("GlobalAlloc")
	pGlobalLock                 = kernel32.NewProc("GlobalLock")
	pGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	pGlobalFree                 = kernel32.NewProc("GlobalFree")
	pGetTickCount               = kernel32.NewProc("GetTickCount")
	pSetDefaultDllDirectories   = kernel32.NewProc("SetDefaultDllDirectories")
	pSetProcessMitigationPolicy = kernel32.NewProc("SetProcessMitigationPolicy")
	pWTSRegisterSessionNotif    = wtsapi32.NewProc("WTSRegisterSessionNotification")
	pWTSUnRegisterSessionNotif  = wtsapi32.NewProc("WTSUnRegisterSessionNotification")
	pShellExecuteW              = shell32.NewProc("ShellExecuteW")
)

// Window styles and messages.
const (
	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsTabStop      = 0x00010000
	wsGroup        = 0x00020000
	wsVScroll      = 0x00200000
	wsClipSiblings = 0x04000000
	wsClipChildren = 0x02000000
	wsPopup        = 0x80000000
	wsDlgFrame     = 0x00400000

	wsExClientEdge    = 0x00000200
	wsExControlParent = 0x00010000
	wsExDlgModalFrame = 0x00000001

	esMultiline   = 0x0004
	esPassword    = 0x0020
	esAutoVScroll = 0x0040
	esAutoHScroll = 0x0080
	esReadOnly    = 0x0800
	esWantReturn  = 0x1000
	esNumber      = 0x2000

	bsPushButton    = 0x0
	bsDefPushButton = 0x1
	bsAutoCheckbox  = 0x3

	cbsDropDownList = 0x3
	cbAddString     = 0x0143
	cbSetCurSel     = 0x014E
	cbGetCurSel     = 0x0147

	wmCreate           = 0x0001
	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmQueryEndSession  = 0x0011
	wmEndSession       = 0x0016
	wmSetFont          = 0x0030
	wmNotify           = 0x004E
	wmKeyDown          = 0x0100
	wmCommand          = 0x0111
	wmTimer            = 0x0113
	wmCtlColorEdit     = 0x0133
	wmCtlColorBtn      = 0x0135
	wmCtlColorStatic   = 0x0138
	wmWTSSessionChange = 0x02B1
	wmDPIChanged       = 0x02E0
	wmApp              = 0x8000

	bnClicked = 0

	emSetSel       = 0x00B1
	emLimitText    = 0x00C5
	emSetCueBanner = 0x1501

	bmGetCheck = 0x00F0

	tcmInsertItemW = 0x133E
	tcmGetCurSel   = 0x130B
	tcmSetCurSel   = 0x130C
	tcmAdjustRect  = 0x1328
	tcnSelChange   = 0xFFFFFDD9 // TCN_FIRST(-550) - 1

	lvmGetItemCount         = 0x1004
	lvmDeleteAllItems       = 0x1009
	lvmGetNextItem          = 0x100C
	lvmGetItemState         = 0x102C
	lvmSetExtendedStyle     = 0x1036
	lvmInsertItemW          = 0x104D
	lvmInsertColumnW        = 0x1061
	lvmSetItemTextW         = 0x1074
	lvsReport               = 0x0001
	lvsShowSelAlways        = 0x0008
	lvsExCheckboxes         = 0x0004
	lvsExFullRowSelect      = 0x0020
	lvsExGridLines          = 0x0001
	lvsExDoubleBuffer       = 0x00010000
	lvcfFmt                 = 0x1
	lvcfWidth               = 0x2
	lvcfText                = 0x4
	lvifText                = 0x1
	lvisStateImageMask      = 0xF000
	lvniSelected            = 0x2
	iccStandardClasses      = 0x4000
	iccTabClasses           = 0x0008
	iccListviewClasses      = 0x0001
	swHide                  = 0
	swShow                  = 5
	swShowNormal            = 1
	swpNoZOrder             = 0x0004
	swpNoActivate           = 0x0010
	smCxScreen              = 0
	smCyScreen              = 1
	colorWindow             = 5
	colorBtnFace            = 15
	idcArrow                = 32512
	idcWait                 = 32514
	idiApplication          = 32512
	mbOK                    = 0x0
	mbOKCancel              = 0x1
	mbYesNo                 = 0x4
	mbIconError             = 0x10
	mbIconWarning           = 0x30
	mbIconInformation       = 0x40
	mbDefButton2            = 0x100
	idOK                    = 1
	idCancel                = 2
	idYes                   = 6
	gmemMoveable            = 0x0002
	cfUnicodeText           = 13
	ofnOverwritePrompt      = 0x00000002
	ofnHideReadOnly         = 0x00000004
	ofnNoChangeDir          = 0x00000008
	ofnPathMustExist        = 0x00000800
	ofnFileMustExist        = 0x00001000
	ofnExplorer             = 0x00080000
	ofnDontAddToRecent      = 0x02000000
	transparent             = 1
	wtsSessionLock          = 0x7
	notifyForThisSession    = 0
	vkReturn                = 0x0D
	vkEscape                = 0x1B
	loadLibrarySearchSystem = 0x00000800
	dpiAwarenessPerMonitor2 = ^uintptr(3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
)

type point struct{ X, Y int32 }

type rect struct{ Left, Top, Right, Bottom int32 }

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type nmhdr struct {
	HwndFrom uintptr
	IDFrom   uintptr
	Code     uint32
}

type tcItem struct {
	Mask      uint32
	State     uint32
	StateMask uint32
	Text      *uint16
	TextMax   int32
	Image     int32
	Param     uintptr
}

type lvColumn struct {
	Mask      uint32
	Fmt       int32
	Cx        int32
	Text      *uint16
	TextMax   int32
	SubItem   int32
	Image     int32
	Order     int32
	CxMin     int32
	CxDefault int32
	CxIdeal   int32
}

type lvItem struct {
	Mask      uint32
	Item      int32
	SubItem   int32
	State     uint32
	StateMask uint32
	Text      *uint16
	TextMax   int32
	Image     int32
	Param     uintptr
	Indent    int32
	GroupID   int32
	Columns   uint32
	PuColumns uintptr
	PiColFmt  uintptr
	Group     int32
}

type openFileName struct {
	StructSize    uint32
	Owner         uintptr
	Instance      uintptr
	Filter        *uint16
	CustomFilter  *uint16
	MaxCustFilter uint32
	FilterIndex   uint32
	File          *uint16
	MaxFile       uint32
	FileTitle     *uint16
	MaxFileTitle  uint32
	InitialDir    *uint16
	Title         *uint16
	Flags         uint32
	FileOffset    uint16
	FileExtension uint16
	DefExt        *uint16
	CustData      uintptr
	Hook          uintptr
	TemplateName  *uint16
	Reserved      uintptr
	Reserved2     uint32
	FlagsEx       uint32
}

type initCommonControlsEx struct {
	Size uint32
	ICC  uint32
}

type lastInputInfo struct {
	Size uint32
	Time uint32
}

// u16 converts a Go string to a NUL-terminated UTF-16 pointer. NUL bytes in
// s are replaced (they would otherwise truncate silently).
func u16(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		p, _ = windows.UTF16PtrFromString(stringsReplaceNUL(s))
	}
	return p
}

func stringsReplaceNUL(s string) string {
	b := []rune(s)
	for i, r := range b {
		if r == 0 {
			b[i] = ' '
		}
	}
	return string(b)
}

func sendMessage(h uintptr, m uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(h, uintptr(m), w, l)
	return r
}

func postMessage(h uintptr, m uint32, w, l uintptr) {
	_, _, _ = pPostMessageW.Call(h, uintptr(m), w, l)
}

func setText(h uintptr, s string) {
	_, _, _ = pSetWindowTextW.Call(h, uintptr(unsafe.Pointer(u16(s))))
}

// getText returns a control's text.
func getText(h uintptr) string {
	buf := getTextUTF16(h)
	s := windows.UTF16ToString(buf)
	return s
}

// getTextUTF16 returns the raw UTF-16 buffer (callers handling secrets wipe it).
func getTextUTF16(h uintptr) []uint16 {
	n, _, _ := pGetWindowTextLengthW.Call(h)
	buf := make([]uint16, n+1)
	_, _, _ = pGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return buf
}

// utf16ToUTF8 converts without creating an immutable Go string (for secrets).
func utf16ToUTF8(u []uint16) []byte {
	end := 0
	for end < len(u) && u[end] != 0 {
		end++
	}
	runes := utf16.Decode(u[:end])
	out := make([]byte, 0, len(runes)*4)
	for _, r := range runes {
		out = utf8.AppendRune(out, r) // No intermediate (immutable, unwipeable) Go string.
	}
	for i := range runes {
		runes[i] = 0
	}
	return out
}

func enable(h uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	_, _, _ = pEnableWindow.Call(h, v)
}

func show(h uintptr, on bool) {
	v := uintptr(swHide)
	if on {
		v = swShow
	}
	_, _, _ = pShowWindow.Call(h, v)
}

func isChecked(h uintptr) bool { return sendMessage(h, bmGetCheck, 0, 0) == 1 }

func moveWindow(h uintptr, x, y, w, hgt int32) {
	_, _, _ = pSetWindowPos.Call(h, 0, uintptr(x), uintptr(y), uintptr(w), uintptr(hgt), swpNoZOrder|swpNoActivate)
}

func messageBox(owner uintptr, text, title string, flags uint32) int {
	r, _, _ := pMessageBoxW.Call(owner, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(title))), uintptr(flags))
	return int(r)
}

func tickCount() uint32 {
	r, _, _ := pGetTickCount.Call()
	return uint32(r)
}

func idleMillis() uint32 {
	lii := lastInputInfo{Size: uint32(unsafe.Sizeof(lastInputInfo{}))}
	r, _, _ := pGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	if r == 0 {
		return 0
	}
	return tickCount() - lii.Time
}

func moduleHandle() uintptr {
	h, _, _ := pGetModuleHandleW.Call(0)
	return h
}

// winPtr converts the address of memory owned by Windows (message
// parameters, GlobalLock results) into a pointer. Such memory is never on the
// Go heap, so the garbage collector cannot move or free it; reading the
// address through a variable keeps the conversion explicit for reviewers.
func winPtr(addr uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr)) // #nosec G103 -- documented Win32 pointer conversion.
}

// callOK reports whether a proc exists (older Windows versions lack some).
func callOK(p *windows.LazyProc) bool { return p.Find() == nil }

var _ = syscall.EINVAL
