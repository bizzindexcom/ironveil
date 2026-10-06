//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/bizzindexcom/ironveil/ironveil-keygen/internal/keystore"
	"github.com/bizzindexcom/ironveil/ironveil-keygen/internal/ledger"
	"github.com/bizzindexcom/ironveil/ironveil-keygen/internal/license"
)

const (
	mainClass = "IronVeilKeygenMain"
	pageClass = "IronVeilKeygenPage"

	clientW = 800 // Logical (96 DPI) client size.
	clientH = 600

	timerIdle      = 1
	idleLockMillis = 10 * 60 * 1000
	wmAsyncDone    = wmApp + 1

	pageIssue  = 0
	pageCheck  = 1
	pageLedger = 2
	pageKey    = 3
)

// Control ids.
const (
	idTab    = 600
	idStatus = 601
	idTitle  = 602

	idName      = 201
	idDomains   = 202
	idType      = 203
	idDays      = 204
	idNever     = 205
	idGenerate  = 206
	idKeyOut    = 207
	idSummary   = 208
	idCopyKey   = 209
	idSaveKey   = 210
	idCopyEmail = 211

	idCheckInput = 301
	idCheckHost  = 302
	idCheckBtn   = 303
	idCheckOut   = 304
	idCopyRevoke = 305

	idList       = 401
	idRefresh    = 402
	idCopySel    = 403
	idRevoke     = 404
	idRevokeList = 405
	idExportCSV  = 406
	idSignFeed   = 407

	idOpenKey    = 501
	idUnlockLast = 502
	idSaveEnc    = 503
	idNewPair    = 504
	idLock       = 505
	idKeyInfo    = 506
	idOpenFolder = 507
)

type ctrl struct {
	h           uintptr
	parent      uintptr
	x, y, w, ht int32
	font        int // 0 normal, 1 heading, 2 small
}

type app struct {
	inst, hwnd, icon uintptr
	tab              uintptr
	pages            [4]uintptr
	ctrls            []*ctrl
	byID             map[int]uintptr
	dpi              uint32
	fonts            [3]uintptr
	whiteBrush       uintptr

	key        *keystore.Key
	keySource  string // "encrypted" or "plain"
	keyPath    string
	keyMatches bool

	lastKey     string
	lastPayload license.Payload
	checkedID   string

	ledgerEntries []ledger.Entry
	dataDir       string
	settings      settings

	busy        bool
	lockPending bool // An auto-lock arrived while background work was running.
	asyncCh     chan func()
}

var (
	theApp     *app
	wndProcPtr = windows.NewCallback(wndProc)
)

func (a *app) scale(v int32) int32 { return int32(int64(v) * int64(a.dpi) / 96) }

// child creates a control with already-scaled coordinates.
func (a *app) child(parent uintptr, class, text string, style uint32, x, y, w, h int32, id int) uintptr {
	ex := uint32(0)
	if class == "EDIT" || class == "SysListView32" {
		ex = wsExClientEdge
	}
	hwnd := createWindow(ex, class, text, wsChild|wsVisible|style, x, y, w, h, parent, uintptr(id), a.inst)
	if hwnd != 0 {
		sendMessage(hwnd, wmSetFont, a.fonts[0], 1)
	}
	return hwnd
}

// add creates a control with logical coordinates and remembers them for DPI changes.
func (a *app) add(parent uintptr, class, text string, style uint32, x, y, w, h int32, id, font int) uintptr {
	hwnd := a.child(parent, class, text, style, a.scale(x), a.scale(y), a.scale(w), a.scale(h), id)
	if hwnd == 0 {
		return 0
	}
	a.ctrls = append(a.ctrls, &ctrl{h: hwnd, parent: parent, x: x, y: y, w: w, ht: h, font: font})
	if font != 0 {
		sendMessage(hwnd, wmSetFont, a.fonts[font], 1)
	}
	if id != 0 {
		a.byID[id] = hwnd
	}
	return hwnd
}

func (a *app) h(id int) uintptr { return a.byID[id] }

func (a *app) makeFonts() {
	for _, f := range a.fonts {
		if f != 0 {
			_, _, _ = pDeleteObject.Call(f)
		}
	}
	mk := func(pt int32, weight int) uintptr {
		h := -int32(int64(pt) * int64(a.dpi) / 72)
		f, _, _ := pCreateFontW.Call(uintptr(h), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(u16("Segoe UI"))))
		return f
	}
	a.fonts[0] = mk(9, 400)
	a.fonts[1] = mk(14, 600)
	a.fonts[2] = mk(8, 400)
}

func run() error {
	a := &app{byID: map[int]uintptr{}, dpi: 96, asyncCh: make(chan func(), 1)}
	theApp = a
	a.inst = moduleHandle()
	a.whiteBrush = sysColorBrush(colorWindow)
	if r, _, _ := pLoadIconW.Call(a.inst, uintptr(unsafe.Pointer(u16("APP")))); r != 0 {
		a.icon = r
	} else {
		a.icon, _, _ = pLoadIconW.Call(0, idiApplication)
	}
	icc := initCommonControlsEx{Size: uint32(unsafe.Sizeof(initCommonControlsEx{})), ICC: iccStandardClasses | iccTabClasses | iccListviewClasses}
	_, _, _ = pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))

	for _, cls := range []struct {
		name string
		bg   uintptr
	}{{mainClass, sysColorBrush(colorBtnFace)}, {pageClass, a.whiteBrush}} {
		wc := wndClassEx{
			Size:       uint32(unsafe.Sizeof(wndClassEx{})),
			WndProc:    wndProcPtr,
			Instance:   a.inst,
			Icon:       a.icon,
			IconSm:     a.icon,
			Cursor:     loadCursor(idcArrow),
			Background: cls.bg,
			ClassName:  u16(cls.name),
		}
		if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			return fmt.Errorf("RegisterClassEx: %v", err)
		}
	}
	style := uint32(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsClipChildren)
	a.hwnd = createWindow(wsExControlParent, mainClass, "IronVeil Keygen "+version, style, 100, 100, 400, 300, 0, 0, a.inst)
	if a.hwnd == 0 {
		return fmt.Errorf("could not create the main window")
	}
	if callOK(pGetDpiForWindow) {
		if d, _, _ := pGetDpiForWindow.Call(a.hwnd); d >= 96 {
			a.dpi = uint32(d)
		}
	}
	a.makeFonts()
	a.resizeToClient()
	a.build()
	a.initState()
	_, _, _ = pShowWindow.Call(a.hwnd, swShowNormal)
	_, _, _ = pUpdateWindow.Call(a.hwnd)
	_, _, _ = pSetTimer.Call(a.hwnd, timerIdle, 15000, 0)
	if callOK(pWTSRegisterSessionNotif) {
		_, _, _ = pWTSRegisterSessionNotif.Call(a.hwnd, notifyForThisSession)
	}

	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		if ok, _, _ := pIsDialogMessageW.Call(a.hwnd, uintptr(unsafe.Pointer(&m))); ok != 0 {
			continue
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	a.lock(false)
	return nil
}

// resizeToClient sizes and centres the window for the current DPI.
func (a *app) resizeToClient() {
	r := rect{0, 0, a.scale(clientW), a.scale(clientH)}
	_, _, _ = pAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&r)), wsOverlapped|wsCaption|wsSysMenu|wsMinimizeBox, 0, wsExControlParent)
	w, h := r.Right-r.Left, r.Bottom-r.Top
	sw, _, _ := pGetSystemMetrics.Call(smCxScreen)
	sh, _, _ := pGetSystemMetrics.Call(smCyScreen)
	x, y := (int32(sw)-w)/2, (int32(sh)-h)/2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	_, _, _ = pSetWindowPos.Call(a.hwnd, 0, uintptr(x), uintptr(y), uintptr(w), uintptr(h), swpNoZOrder|swpNoActivate)
}

// pageRect returns the tab display area in logical units.
func (a *app) pageRect() (x, y, w, h int32) {
	return 14, 104, clientW - 28, clientH - 116
}

func (a *app) build() {
	a.add(a.hwnd, "STATIC", "IronVeil Keygen", 0, 16, 8, 500, 30, idTitle, 1)
	a.add(a.hwnd, "STATIC", "", 0, 16, 40, 768, 38, idStatus, 0)
	a.tab = a.add(a.hwnd, "SysTabControl32", "", wsTabStop|wsClipSiblings, 12, 82, clientW-24, clientH-92, idTab, 0)
	for i, title := range []string{"Issue license", "Check a key", "Issued licenses", "Signing key"} {
		it := tcItem{Mask: 1, Text: u16(title)} // TCIF_TEXT
		sendMessage(a.tab, tcmInsertItemW, uintptr(i), uintptr(unsafe.Pointer(&it)))
	}
	px, py, pw, ph := a.pageRect()
	for i := range a.pages {
		a.pages[i] = a.add(a.hwnd, pageClass, "", wsClipChildren, px, py, pw, ph, 0, 0)
		_, _, _ = pSetWindowPos.Call(a.pages[i], 0, 0, 0, 0, 0, 0x0001|0x0002|0x0010) // HWND_TOP, NOSIZE|NOMOVE|NOACTIVATE
		setExStyleControlParent(a.pages[i])
	}
	a.buildIssue(a.pages[pageIssue])
	a.buildCheck(a.pages[pageCheck])
	a.buildLedger(a.pages[pageLedger])
	a.buildKey(a.pages[pageKey])
	a.showPage(pageKey)
}

var pSetWindowLongPtrW = user32.NewProc("SetWindowLongPtrW")
var pGetWindowLongPtrW = user32.NewProc("GetWindowLongPtrW")

func setExStyleControlParent(h uintptr) {
	const gwlExStyle = ^uintptr(19) // -20
	cur, _, _ := pGetWindowLongPtrW.Call(h, gwlExStyle)
	_, _, _ = pSetWindowLongPtrW.Call(h, gwlExStyle, cur|wsExControlParent)
}

func (a *app) buildIssue(p uintptr) {
	lbl := func(text string, y int32) { a.add(p, "STATIC", text, 0, 16, y, 140, 22, 0, 0) }
	lbl("Customer name", 16)
	a.add(p, "EDIT", "", wsTabStop|esAutoHScroll, 160, 13, 580, 24, idName, 0)
	sendMessage(a.h(idName), emLimitText, 200, 0)
	sendMessage(a.h(idName), emSetCueBanner, 1, uintptr(unsafe.Pointer(u16("e.g. Acme Ltd"))))
	lbl("Domains", 50)
	a.add(p, "EDIT", "", wsTabStop|esMultiline|esAutoVScroll|esWantReturn|wsVScroll, 160, 47, 580, 78, idDomains, 0)
	sendMessage(a.h(idDomains), emLimitText, 4000, 0)
	a.add(p, "STATIC", "One per line. example.com also covers www.example.com. *.example.com covers the domain and all subdomains. * means any site (owner licenses only).", 0, 160, 128, 580, 32, 0, 2)
	lbl("License type", 172)
	a.add(p, "COMBOBOX", "", wsTabStop|cbsDropDownList|wsVScroll, 160, 168, 240, 200, idType, 0)
	for _, s := range []string{"Paid (customer)", "Complimentary (free Pro)", "Owner (your own sites)"} {
		sendMessage(a.h(idType), cbAddString, 0, uintptr(unsafe.Pointer(u16(s))))
	}
	sendMessage(a.h(idType), cbSetCurSel, 0, 0)
	lbl("Valid for (days)", 208)
	a.add(p, "EDIT", "365", wsTabStop|esNumber, 160, 205, 80, 24, idDays, 0)
	sendMessage(a.h(idDays), emLimitText, 5, 0)
	a.add(p, "BUTTON", "Never expires", wsTabStop|bsAutoCheckbox, 256, 206, 200, 22, idNever, 0)
	a.add(p, "BUTTON", "Generate license key", wsTabStop|bsPushButton, 160, 242, 220, 32, idGenerate, 0)
	lbl("License key", 290)
	a.add(p, "EDIT", "", wsTabStop|esMultiline|esReadOnly|esAutoVScroll|wsVScroll, 160, 286, 580, 84, idKeyOut, 0)
	a.add(p, "STATIC", "", 0, 160, 374, 580, 36, idSummary, 2)
	a.add(p, "BUTTON", "Copy key", wsTabStop, 160, 414, 130, 30, idCopyKey, 0)
	a.add(p, "BUTTON", "Save as text file…", wsTabStop, 298, 414, 150, 30, idSaveKey, 0)
	a.add(p, "BUTTON", "Copy customer email", wsTabStop, 456, 414, 170, 30, idCopyEmail, 0)
}

func (a *app) buildCheck(p uintptr) {
	a.add(p, "STATIC", "License key", 0, 16, 16, 140, 22, 0, 0)
	a.add(p, "EDIT", "", wsTabStop|esMultiline|esAutoVScroll|wsVScroll, 160, 13, 580, 76, idCheckInput, 0)
	sendMessage(a.h(idCheckInput), emLimitText, 8192, 0)
	a.add(p, "STATIC", "Site domain (optional)", 0, 16, 102, 140, 36, 0, 0)
	a.add(p, "EDIT", "", wsTabStop|esAutoHScroll, 160, 100, 300, 24, idCheckHost, 0)
	sendMessage(a.h(idCheckHost), emLimitText, 260, 0)
	sendMessage(a.h(idCheckHost), emSetCueBanner, 1, uintptr(unsafe.Pointer(u16("e.g. customer.com"))))
	a.add(p, "BUTTON", "Check key", wsTabStop, 470, 97, 130, 30, idCheckBtn, 0)
	a.add(p, "STATIC", "Result", 0, 16, 144, 140, 22, 0, 0)
	a.add(p, "EDIT", "", wsTabStop|esMultiline|esReadOnly|esAutoVScroll|wsVScroll, 160, 140, 580, 250, idCheckOut, 0)
	a.add(p, "BUTTON", "Copy revocation entry", wsTabStop, 160, 400, 220, 30, idCopyRevoke, 0)
}

func (a *app) buildLedger(p uintptr) {
	lv := a.add(p, "SysListView32", "", wsTabStop|lvsReport|lvsShowSelAlways, 16, 14, 724, 312, idList, 0)
	sendMessage(lv, lvmSetExtendedStyle, 0, lvsExCheckboxes|lvsExFullRowSelect|lvsExGridLines|lvsExDoubleBuffer)
	for i, c := range []struct {
		t string
		w int32
	}{{"Issued", 98}, {"Customer", 124}, {"Type", 92}, {"Domains", 146}, {"Expires", 82}, {"Status", 60}, {"ID", 98}} {
		col := lvColumn{Mask: lvcfText | lvcfWidth, Cx: a.scale(c.w), Text: u16(c.t)}
		sendMessage(lv, lvmInsertColumnW, uintptr(i), uintptr(unsafe.Pointer(&col)))
	}
	y := int32(334)
	a.add(p, "BUTTON", "Refresh", wsTabStop, 16, y, 90, 30, idRefresh, 0)
	a.add(p, "BUTTON", "Copy selected key", wsTabStop, 114, y, 150, 30, idCopySel, 0)
	a.add(p, "BUTTON", "Revoke checked…", wsTabStop, 272, y, 140, 30, idRevoke, 0)
	a.add(p, "BUTTON", "Copy revocation list", wsTabStop, 420, y, 170, 30, idRevokeList, 0)
	a.add(p, "BUTTON", "Export CSV…", wsTabStop, 598, y, 142, 30, idExportCSV, 0)
	a.add(p, "BUTTON", "Sign revocation feed…", wsTabStop, 16, 372, 210, 30, idSignFeed, 0)
	a.add(p, "STATIC", "To revoke keys: tick them and click Revoke checked. Then click Sign revocation feed, choose your feed rules file (rules.json, like tools/feed-example.json; raise its \"version\" every time) and upload the signed signatures.json to your feed URL. Revoked IDs are merged in automatically; Pro sites drop to Free after their next daily feed update.", 0, 16, 410, 724, 56, 0, 2)
}

func (a *app) buildKey(p uintptr) {
	a.add(p, "STATIC", "IronVeil licenses are signed with your Ed25519 owner key. Open the encrypted keystore (.ivkey) or, the first time, the owner-kit file ironveil-owner-private.key and save an encrypted copy. The key stays in memory only while unlocked and locks after 10 minutes without input or when Windows locks.", 0, 16, 14, 724, 52, 0, 0)
	y := int32(74)
	a.add(p, "BUTTON", "Open key file…", wsTabStop, 16, y, 150, 32, idOpenKey, 0)
	a.add(p, "BUTTON", "Unlock last keystore", wsTabStop, 174, y, 170, 32, idUnlockLast, 0)
	a.add(p, "BUTTON", "Save encrypted copy…", wsTabStop, 352, y, 180, 32, idSaveEnc, 0)
	a.add(p, "BUTTON", "Lock now", wsTabStop, 540, y, 110, 32, idLock, 0)
	a.add(p, "EDIT", "", wsTabStop|esMultiline|esReadOnly|esAutoVScroll|wsVScroll, 16, 116, 724, 220, idKeyInfo, 0)
	a.add(p, "BUTTON", "Create new key pair…", wsTabStop, 16, 346, 190, 32, idNewPair, 0)
	a.add(p, "BUTTON", "Open data folder", wsTabStop, 214, 346, 160, 32, idOpenFolder, 0)
	a.add(p, "STATIC", "Only create a new key pair if the owner key was lost or exposed. A new key works only after its public key is placed in the plugin (includes/class-license.php → PUBLIC_KEY), checksums.json is rebuilt and the plugin is re-released; licenses from the old key must then be re-issued.", 0, 16, 388, 724, 52, 0, 2)
}

func (a *app) showPage(i int) {
	for j, p := range a.pages {
		show(p, j == i)
	}
	sendMessage(a.tab, tcmSetCurSel, uintptr(i), 0)
	if i == pageLedger {
		a.refreshLedger()
	}
}

// relayout re-applies logical positions after a DPI change.
func (a *app) relayout() {
	a.makeFonts()
	for _, c := range a.ctrls {
		moveWindow(c.h, a.scale(c.x), a.scale(c.y), a.scale(c.w), a.scale(c.ht))
		sendMessage(c.h, wmSetFont, a.fonts[c.font], 1)
	}
}

func wndProc(hwnd, m, wp, lp uintptr) uintptr {
	a := theApp
	if a == nil || a.hwnd == 0 {
		r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
		return r
	}
	switch uint32(m) {
	case wmCommand:
		if lp != 0 && (wp>>16)&0xFFFF == bnClicked {
			a.onCommand(int(wp & 0xFFFF))
			return 0
		}
	case wmNotify:
		hdr := (*nmhdr)(winPtr(lp)) // lParam of WM_NOTIFY points to an NMHDR owned by the sender.
		if hdr.HwndFrom == a.tab && hdr.Code == tcnSelChange {
			i := int(sendMessage(a.tab, tcmGetCurSel, 0, 0))
			a.showPage(i)
			return 0
		}
	case wmCtlColorStatic:
		_, _, _ = pSetBkMode.Call(wp, transparent)
		if hwnd == a.hwnd {
			return sysColorBrush(colorBtnFace)
		}
		return a.whiteBrush
	case wmCtlColorBtn:
		if hwnd != a.hwnd {
			return a.whiteBrush
		}
	case wmTimer:
		if wp == timerIdle && a.key != nil && idleMillis() > idleLockMillis {
			a.autoLock()
		}
		return 0
	case wmWTSSessionChange:
		if wp == wtsSessionLock && a.key != nil {
			a.autoLock()
		}
		return 0
	case wmAsyncDone:
		select {
		case fn := <-a.asyncCh:
			fn()
		default:
		}
		return 0
	case wmDPIChanged:
		if hwnd == a.hwnd {
			a.dpi = uint32(wp & 0xFFFF)
			r := (*rect)(winPtr(lp)) // lParam of WM_DPICHANGED points to a RECT owned by Windows.
			_, _, _ = pSetWindowPos.Call(hwnd, 0, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), swpNoZOrder|swpNoActivate)
			a.relayout()
			return 0
		}
	case wmQueryEndSession:
		return 1
	case wmEndSession:
		a.lock(false)
		return 0
	case wmClose:
		if hwnd == a.hwnd {
			if a.busy {
				return 0
			}
			a.lock(false)
			_, _, _ = pDestroyWindow.Call(hwnd)
			return 0
		}
	case wmDestroy:
		if hwnd == a.hwnd {
			_, _, _ = pKillTimer.Call(hwnd, timerIdle)
			if callOK(pWTSUnRegisterSessionNotif) {
				_, _, _ = pWTSUnRegisterSessionNotif.Call(hwnd)
			}
			for _, f := range a.fonts {
				_, _, _ = pDeleteObject.Call(f)
			}
			_, _, _ = pPostQuitMessage.Call(0)
			return 0
		}
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

// runAsync runs slow work (Argon2id) off the UI thread and finishes on it.
func (a *app) runAsync(status string, work func() (any, error), done func(any, error)) {
	if a.busy {
		return
	}
	a.busy = true
	enable(a.hwnd, false)
	a.setStatusText(status)
	_, _, _ = pSetCursor.Call(loadCursor(idcWait))
	go func() {
		res, err := safeCall(work)
		a.asyncCh <- func() {
			a.busy = false
			enable(a.hwnd, true)
			_, _, _ = pSetCursor.Call(loadCursor(idcArrow))
			a.updateStatus() // Before done: it may show a modal box or set its own status text.
			done(res, err)
			if a.lockPending {
				a.lockPending = false
				a.lock(true)
			}
		}
		postMessage(a.hwnd, wmAsyncDone, 0, 0)
	}()
}

// safeCall turns a panic in background work into an error.
func safeCall(fn func() (any, error)) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()
	return fn()
}
