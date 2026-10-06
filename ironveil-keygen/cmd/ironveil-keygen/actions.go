//go:build windows

package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/bizzindexcom/ironveil/ironveil-keygen/internal/feed"
	"github.com/bizzindexcom/ironveil/ironveil-keygen/internal/keystore"
	"github.com/bizzindexcom/ironveil/ironveil-keygen/internal/ledger"
	"github.com/bizzindexcom/ironveil/ironveil-keygen/internal/license"
)

const appTitle = "IronVeil Keygen"

type settings struct {
	LastKeystore string `json:"last_keystore,omitempty"`
}

// ---------------------------------------------------------------- State.

func (a *app) initState() {
	if dir, err := os.UserConfigDir(); err == nil {
		a.dataDir = filepath.Join(dir, "IronVeil Keygen")
		if err := os.MkdirAll(a.dataDir, 0o700); err == nil {
			_ = keystore.RestrictDir(a.dataDir)
		}
	}
	a.loadSettings()
	a.updateStatus()
}

func (a *app) settingsPath() string { return filepath.Join(a.dataDir, "settings.json") }
func (a *app) ledgerPath() string   { return filepath.Join(a.dataDir, "issued-licenses.jsonl") }

func (a *app) loadSettings() {
	if a.dataDir == "" {
		return
	}
	b, err := os.ReadFile(a.settingsPath())
	if err != nil || len(b) > 64*1024 {
		return
	}
	_ = json.Unmarshal(b, &a.settings)
}

func (a *app) saveSettings() {
	if a.dataDir == "" {
		return
	}
	b, _ := json.MarshalIndent(a.settings, "", "  ")
	_ = os.WriteFile(a.settingsPath(), b, 0o600)
}

func (a *app) setStatusText(s string) { setText(a.h(idStatus), s) }

// updateStatus refreshes the status line, the key page and button states.
func (a *app) updateStatus() {
	loaded := a.key != nil
	var status string
	switch {
	case !loaded:
		status = "Signing key: locked. Open your keystore on the Signing key tab to issue licenses. Checking keys works without it."
	case a.keyMatches:
		status = "Signing key: unlocked and matches the IronVeil Security plugin. Locks after 10 minutes without input."
	default:
		status = "Signing key: unlocked, but it does NOT match the public key built into the IronVeil Security plugin."
	}
	if loaded && a.keySource == "plain" {
		status += " Unencrypted key file: save an encrypted copy."
	}
	a.setStatusText(status)

	for _, id := range []int{idGenerate, idSignFeed} {
		enable(a.h(id), loaded)
	}
	hasKey := a.lastKey != ""
	for _, id := range []int{idCopyKey, idSaveKey, idCopyEmail} {
		enable(a.h(id), hasKey)
	}
	enable(a.h(idCopyRevoke), a.checkedID != "")
	enable(a.h(idSaveEnc), loaded)
	enable(a.h(idLock), loaded)
	_, err := os.Stat(a.settings.LastKeystore)
	enable(a.h(idUnlockLast), !loaded && a.settings.LastKeystore != "" && err == nil)
	enable(a.h(idDays), !isChecked(a.h(idNever)))

	var b strings.Builder
	if !loaded {
		b.WriteString("Status: LOCKED\r\n")
		if a.settings.LastKeystore != "" {
			fmt.Fprintf(&b, "Last keystore: %s\r\n", a.settings.LastKeystore)
		}
	} else {
		b.WriteString("Status: UNLOCKED\r\n")
		if a.keySource == "encrypted" {
			b.WriteString("Format: encrypted keystore (Argon2id + XChaCha20-Poly1305)\r\n")
		} else {
			b.WriteString("Format: UNENCRYPTED owner-kit key file. Click \"Save encrypted copy…\", then move the original file to offline storage.\r\n")
		}
		fmt.Fprintf(&b, "File: %s\r\nPublic key: %s\r\n", a.keyPath, a.key.PublicBase64())
		if a.keyMatches {
			b.WriteString("Plugin match: YES. Licenses signed with this key are accepted by IronVeil Security.\r\n")
		} else {
			fmt.Fprintf(&b, "Plugin match: NO. The plugin expects %s.\r\nLicenses from this key are rejected unless you put its public key in includes/class-license.php (PUBLIC_KEY).\r\n", license.PluginPublicKey)
		}
	}
	b.WriteString("\r\nData folder (issued-licenses log, settings): ")
	b.WriteString(a.dataDir)
	b.WriteString("\r\nThis app works fully offline and never connects to the internet.")
	setText(a.h(idKeyInfo), b.String())
}

// lock wipes the key from memory.
func (a *app) lock(notify bool) {
	if a.key == nil {
		return
	}
	a.key.Wipe()
	a.key = nil
	a.keyPath, a.keySource, a.keyMatches = "", "", false
	if a.hwnd != 0 {
		a.updateStatus()
	}
	_ = notify
}

// autoLock handles the idle timer and Windows session lock. Background work
// may be using key material, so the lock then waits until it has finished.
func (a *app) autoLock() {
	if a.busy {
		a.lockPending = true
		return
	}
	a.lock(true)
}

func (a *app) setKey(k *keystore.Key, source, path string) {
	a.lock(false)
	a.key = k
	a.keySource = source
	a.keyPath = path
	a.keyMatches = k.Matches(license.PluginPublicKey)
	a.updateStatus()
}

func (a *app) warn(text string) { messageBox(a.hwnd, text, appTitle, mbOK|mbIconWarning) }
func (a *app) fail(text string) { messageBox(a.hwnd, text, appTitle, mbOK|mbIconError) }
func (a *app) info(text string) { messageBox(a.hwnd, text, appTitle, mbOK|mbIconInformation) }
func (a *app) ask(text string) bool {
	return messageBox(a.hwnd, text, appTitle, mbYesNo|mbIconWarning|mbDefButton2) == idYes
}

// ---------------------------------------------------------------- Commands.

func (a *app) onCommand(id int) {
	if a.busy {
		return
	}
	switch id {
	case idNever:
		enable(a.h(idDays), !isChecked(a.h(idNever)))
	case idGenerate:
		a.generate()
	case idCopyKey:
		a.copy(a.lastKey, "License key copied.")
	case idSaveKey:
		a.saveKeyText()
	case idCopyEmail:
		a.copy(a.emailText(), "Customer email text copied.")
	case idCheckBtn:
		a.checkKey()
	case idCopyRevoke:
		a.copy(license.RevocationJSON([]string{a.checkedID}), "Revocation entry copied. To revoke this key, find it under Issued licenses, revoke it there and sign a new feed.")
	case idRefresh:
		a.refreshLedger()
	case idCopySel:
		a.copySelectedKey()
	case idRevoke:
		a.revokeChecked()
	case idRevokeList:
		a.copy(license.RevocationJSON(ledger.RevokedIDs(a.ledgerEntries)), "Revocation list copied.")
	case idExportCSV:
		a.exportCSV()
	case idSignFeed:
		a.signFeed()
	case idOpenKey:
		a.openKeyFile("")
	case idUnlockLast:
		a.openKeyFile(a.settings.LastKeystore)
	case idSaveEnc:
		a.saveEncrypted(a.key, "", func(p string, err error) {
			if p != "" && err == nil {
				a.adoptSaved(p)
			}
		})
	case idLock:
		a.lock(true)
	case idNewPair:
		a.newKeyPair()
	case idOpenFolder:
		if a.dataDir != "" {
			openFolder(a.dataDir)
		}
	}
}

func (a *app) copy(text, okMsg string) {
	if text == "" {
		return
	}
	if err := copyToClipboard(a.hwnd, text); err != nil {
		a.fail("Could not copy: " + err.Error())
		return
	}
	a.setStatusText(okMsg)
}

// ---------------------------------------------------------------- Issue.

func (a *app) generate() {
	if a.key == nil {
		a.warn("Unlock your signing key first (Signing key tab).")
		return
	}
	if !a.keyMatches && !a.ask("The loaded key does not match the public key built into IronVeil Security, so the plugin will REJECT licenses signed with it.\n\nOnly continue if you replaced PUBLIC_KEY in the plugin with this key's public key.\n\nIssue the license anyway?") {
		return
	}
	types := []string{license.TypePaid, license.TypeComplimentary, license.TypeOwner}
	typ := license.TypePaid
	if sel := int(sendMessage(a.h(idType), cbGetCurSel, 0, 0)); sel >= 0 && sel < len(types) {
		typ = types[sel]
	}
	days := 0
	if !isChecked(a.h(idNever)) {
		v, err := strconv.Atoi(strings.TrimSpace(getText(a.h(idDays))))
		if err != nil || v < 1 || v > license.MaxDays {
			a.warn(fmt.Sprintf("Enter the number of days the license is valid (1 to %d), or tick \"Never expires\".", license.MaxDays))
			return
		}
		days = v
	}
	req := license.Request{
		Name:    getText(a.h(idName)),
		Type:    typ,
		Domains: []string{getText(a.h(idDomains))},
		Days:    days,
	}
	_, domains, err := license.ValidateRequest(req)
	if err != nil {
		a.warn(capitalize(err.Error()) + ".")
		return
	}
	for _, d := range domains {
		if d == "*" && !a.ask("This owner license works on ANY website. Anyone who gets it has Pro everywhere.\n\nKeep it private and revoke it if it leaks. Continue?") {
			return
		}
	}
	key, p, err := license.Issue(req, a.key.Private(), rand.Reader, time.Now())
	if err != nil {
		a.fail("Could not issue the license: " + err.Error())
		return
	}
	a.lastKey, a.lastPayload = key, p
	setText(a.h(idKeyOut), key)
	setText(a.h(idDomains), strings.Join(p.Domains, "\r\n"))
	setText(a.h(idSummary), fmt.Sprintf("ID %s · %s · %s · %s", p.ID, p.Type, expiryText(p.Expires), strings.Join(p.Domains, ", ")))
	entry := ledger.Entry{Event: "issued", ID: p.ID, Name: p.Name, Type: p.Type, Domains: p.Domains, Issued: p.Issued, Expires: p.Expires, Key: key}
	recorded := false
	if a.dataDir == "" {
		a.warn("The license was created, but there is no data folder to record it in. Save it as a text file.")
	} else if err := ledger.Append(a.ledgerPath(), entry, keystore.RestrictFile); err != nil {
		a.warn("The license was created, but it could not be recorded in the issued-licenses log: " + err.Error() + "\n\nSave it as a text file so you can revoke it later.")
	} else {
		recorded = true
		a.refreshLedger()
	}
	a.updateStatus()
	if recorded {
		a.setStatusText("License " + p.ID + " issued and recorded. Copy it or save it as a text file.")
	} else {
		a.setStatusText("License " + p.ID + " issued but NOT recorded in the log. Save it as a text file.")
	}
}

func expiryText(exp int64) string {
	if exp == 0 {
		return "never expires"
	}
	return "expires " + time.Unix(exp, 0).UTC().Format("2006-01-02")
}

func (a *app) emailText() string {
	if a.lastKey == "" {
		return ""
	}
	p := a.lastPayload
	expiry := "never (lifetime license)"
	if p.Expires != 0 {
		expiry = time.Unix(p.Expires, 0).UTC().Format("2006-01-02") + " (UTC)"
	}
	return fmt.Sprintf("Hello %s,\r\n\r\nHere is your IronVeil Security Pro license key:\r\n\r\n%s\r\n\r\nValid for: %s\r\nExpiry: %s\r\n\r\nTo activate it, sign in to WordPress, open IronVeil > Upgrade to Pro, paste the key and click \"Activate Pro\". The key only works on the domains listed above.\r\n\r\nLicense ID: %s\r\n",
		p.Name, a.lastKey, strings.Join(p.Domains, ", "), expiry, p.ID)
}

func (a *app) saveKeyText() {
	if a.lastKey == "" {
		return
	}
	name := "ironveil-license-" + sanitizeFileName(a.lastPayload.Name) + ".txt"
	path, ok := fileDialog(a.hwnd, true, "Save license key", filterUTF16("Text files (*.txt)", "*.txt"), "txt", name, "")
	if !ok {
		return
	}
	if err := os.WriteFile(path, []byte(a.emailText()), 0o600); err != nil {
		a.fail("Could not save the file: " + err.Error())
		return
	}
	a.setStatusText("Saved " + path)
}

func sanitizeFileName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '.':
			b.WriteRune('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "customer"
	}
	return out
}

// ---------------------------------------------------------------- Check.

func (a *app) checkKey() {
	key := getText(a.h(idCheckInput))
	host := strings.TrimSpace(getText(a.h(idCheckHost)))
	if host != "" {
		h, err := license.NormalizeDomain(host)
		if err != nil || strings.Contains(h, "*") {
			a.warn("Enter the site's domain, for example customer.com.")
			return
		}
		host = h
	}
	now := time.Now()
	st := license.Verify(key, license.PluginPublicKeyBytes(), host, now)
	signer := "the IronVeil Security plugin's built-in key"
	if st.Reason == license.ReasonSignature && a.key != nil && !a.keyMatches {
		if st2 := license.Verify(key, a.key.Public(), host, now); st2.Reason != license.ReasonSignature {
			st, signer = st2, "your loaded key (NOT the plugin's built-in key)"
		}
	}
	var b strings.Builder
	b.WriteString(st.Message())
	b.WriteString("\r\n")
	a.checkedID = ""
	if st.Payload != nil && st.Reason != license.ReasonSignature {
		p := st.Payload
		a.checkedID = p.ID
		fmt.Fprintf(&b, "Signed by: %s\r\n\r\nCustomer: %s\r\nType: %s\r\nDomains: %s\r\nIssued: %s UTC\r\nExpiry: %s\r\nLicense ID: %s\r\n",
			signer, p.Name, p.Type, strings.Join(p.Domains, ", "), time.Unix(p.Issued, 0).UTC().Format("2006-01-02 15:04"), expiryText(p.Expires), p.ID)
		if host == "" {
			b.WriteString("\r\nEnter a site domain to check whether the key covers it.")
		}
		for _, e := range a.ledgerEntriesOrRead() {
			if e.ID == p.ID && e.Revoked {
				b.WriteString("\r\nYour issued-licenses log marks this key as REVOKED.")
			}
		}
	} else if st.Reason == license.ReasonSignature {
		b.WriteString("\r\nDo not trust any information inside this key.")
	}
	setText(a.h(idCheckOut), b.String())
	a.updateStatus()
}

// ---------------------------------------------------------------- Ledger.

func (a *app) ledgerEntriesOrRead() []ledger.Entry {
	if a.ledgerEntries == nil && a.dataDir != "" {
		a.ledgerEntries, _, _ = ledger.Read(a.ledgerPath())
	}
	return a.ledgerEntries
}

func (a *app) refreshLedger() {
	lv := a.h(idList)
	sendMessage(lv, lvmDeleteAllItems, 0, 0)
	if a.dataDir == "" {
		return
	}
	entries, skipped, err := ledger.Read(a.ledgerPath())
	if err != nil {
		a.fail("Could not read the issued-licenses log: " + err.Error())
		return
	}
	a.ledgerEntries = entries
	now := time.Now().Unix()
	for i, e := range entries {
		status := "Active"
		switch {
		case e.Revoked:
			status = "Revoked"
		case e.Expires != 0 && e.Expires < now:
			status = "Expired"
		}
		exp := "never"
		if e.Expires != 0 {
			exp = time.Unix(e.Expires, 0).UTC().Format("2006-01-02")
		}
		cols := []string{time.Unix(e.Issued, 0).UTC().Format("2006-01-02"), e.Name, e.Type, strings.Join(e.Domains, ", "), exp, status, e.ID}
		it := lvItem{Mask: lvifText, Item: int32(i), Text: u16(cols[0])}
		idx := sendMessage(lv, lvmInsertItemW, 0, uintptr(unsafe.Pointer(&it)))
		for c := 1; c < len(cols); c++ {
			sub := lvItem{SubItem: int32(c), Text: u16(cols[c])}
			sendMessage(lv, lvmSetItemTextW, idx, uintptr(unsafe.Pointer(&sub)))
		}
	}
	msg := fmt.Sprintf("%d license(s) in the issued-licenses log.", len(entries))
	if skipped > 0 {
		msg += fmt.Sprintf(" %d damaged line(s) were skipped.", skipped)
	}
	a.setStatusText(msg)
}

func (a *app) checkedRows() []int {
	lv := a.h(idList)
	n := int(sendMessage(lv, lvmGetItemCount, 0, 0))
	var out []int
	for i := 0; i < n && i < len(a.ledgerEntries); i++ {
		if (sendMessage(lv, lvmGetItemState, uintptr(i), lvisStateImageMask)>>12)&0xF == 2 {
			out = append(out, i)
		}
	}
	return out
}

func (a *app) copySelectedKey() {
	lv := a.h(idList)
	i := int(int32(sendMessage(lv, lvmGetNextItem, ^uintptr(0), lvniSelected)))
	if i < 0 || i >= len(a.ledgerEntries) {
		a.warn("Click a license in the list first.")
		return
	}
	a.copy(a.ledgerEntries[i].Key, "Key of license "+a.ledgerEntries[i].ID+" copied.")
}

func (a *app) revokeChecked() {
	rows := a.checkedRows()
	if len(rows) == 0 {
		a.warn("Tick the licenses you want to revoke first.")
		return
	}
	var names []string
	for _, i := range rows {
		names = append(names, fmt.Sprintf("%s (%s)", a.ledgerEntries[i].Name, a.ledgerEntries[i].ID))
	}
	if !a.ask(fmt.Sprintf("Mark %d license(s) as revoked?\n\n%s\n\nThen click Sign revocation feed and upload the signed signatures.json: the plugin only learns about revocations from the feed.", len(rows), strings.Join(names, "\n"))) {
		return
	}
	for _, i := range rows {
		if err := ledger.Append(a.ledgerPath(), ledger.Entry{Event: "revoked", ID: a.ledgerEntries[i].ID}, keystore.RestrictFile); err != nil {
			a.fail("Could not record the revocation: " + err.Error())
			return
		}
	}
	a.refreshLedger()
	a.copy(license.RevocationJSON(ledger.RevokedIDs(a.ledgerEntries)), "Revocations recorded. Next: Sign revocation feed and upload it. (The revocation list is also on the clipboard.)")
}

func (a *app) exportCSV() {
	if len(a.ledgerEntries) == 0 {
		a.warn("There are no issued licenses to export yet.")
		return
	}
	path, ok := fileDialog(a.hwnd, true, "Export issued licenses", filterUTF16("CSV files (*.csv)", "*.csv"), "csv", "ironveil-issued-licenses.csv", "")
	if !ok {
		return
	}
	if err := os.WriteFile(path, []byte(ledger.CSV(a.ledgerEntries)), 0o600); err != nil {
		a.fail("Could not export: " + err.Error())
		return
	}
	a.setStatusText("Exported to " + path + " (license keys are not included).")
}

// signFeed signs the owner's feed rules file with every revocation from the
// log merged in, producing the signatures.json that sites download.
func (a *app) signFeed() {
	if a.key == nil {
		a.warn("Unlock your signing key first (Signing key tab).")
		return
	}
	if !a.keyMatches && !a.ask("The loaded key does not match the public key built into IronVeil Security. Sites only accept this feed if they set this key as their custom feed key.\n\nSign the feed anyway?") {
		return
	}
	src, ok := fileDialog(a.hwnd, false, "Choose your feed rules file (rules.json)", filterUTF16("JSON files (*.json)", "*.json", "All files (*.*)", "*.*"), "", "", "")
	if !ok {
		return
	}
	rules, err := readLimited(src, feed.MaxDocBytes)
	if err != nil {
		a.fail("Could not read the rules file: " + err.Error())
		return
	}
	entries := a.ledgerEntriesOrRead()
	doc, sum, err := feed.Sign(rules, ledger.RevokedIDs(entries), a.key.Private(), time.Now())
	if err != nil {
		a.fail("The feed was not signed: " + err.Error() + ".")
		return
	}
	msg := fmt.Sprintf("Sign signature feed version %d?\n\nRules: %d PHP, %d JS, %d config\nRevoked licenses: %d\nSites accept it until: %s UTC\n\nSites refuse a feed whose version is lower than the one they already have, so this version must be higher than your last published feed.",
		sum.Version, sum.Rules["php"], sum.Rules["js"], sum.Rules["config"], sum.Revoked, time.Unix(sum.Expires, 0).UTC().Format("2006-01-02 15:04"))
	if !a.ask(msg) {
		return
	}
	dst, ok := fileDialog(a.hwnd, true, "Save signed feed", filterUTF16("JSON files (*.json)", "*.json"), "json", "signatures.json", filepath.Dir(src))
	if !ok {
		return
	}
	if sameFile(src, dst) {
		a.warn("Choose a different file: saving over the rules file would lose your rules.")
		return
	}
	if err := os.WriteFile(dst, doc, 0o644); err != nil { // #nosec G306 -- a signed feed is public by design.
		a.fail("Could not save the signed feed: " + err.Error())
		return
	}
	a.setStatusText(fmt.Sprintf("Signed feed version %d (%d revoked) saved to %s. Upload it to your feed URL.", sum.Version, sum.Revoked, dst))
}

// readLimited reads a file, refusing anything larger than max bytes.
func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path chosen by the user in a file dialog.
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("the file is larger than %d bytes", max)
	}
	return b, nil
}

func sameFile(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

// ---------------------------------------------------------------- Key management.

func (a *app) openKeyFile(path string) {
	if path == "" {
		var ok bool
		path, ok = fileDialog(a.hwnd, false, "Open IronVeil signing key", filterUTF16("IronVeil keys (*.ivkey;*.key)", "*.ivkey;*.key", "All files (*.*)", "*.*"), "", "", "")
		if !ok {
			return
		}
	}
	data, err := keystore.ReadFile(path)
	if err != nil {
		a.fail("Could not read the key file: " + err.Error())
		return
	}
	if !keystore.IsEncrypted(data) {
		k, err := keystore.ParsePlain(data)
		keystore.Wipe(data)
		if err != nil {
			a.fail("This is not an IronVeil signing key: " + err.Error())
			return
		}
		a.setKey(k, "plain", path)
		a.showPage(pageKey)
		if a.ask("This key file is NOT encrypted: anyone who copies it can create IronVeil Pro licenses.\n\nSave an encrypted copy now? Afterwards, move the original file to offline storage (for example an encrypted USB drive).") {
			a.saveEncrypted(k, filepath.Dir(path), func(p string, err error) {
				if p != "" && err == nil {
					a.adoptSaved(p)
				}
			})
		}
		return
	}
	pass, ok := askPassphrase(a, "Unlock signing key", "Enter the passphrase for "+filepath.Base(path)+":", false)
	if !ok {
		return
	}
	a.runAsync("Unlocking (deriving the key from your passphrase)…", func() (any, error) {
		defer keystore.Wipe(pass)
		k, err := keystore.Open(data, pass)
		if err != nil {
			time.Sleep(700 * time.Millisecond) // Small extra cost per wrong guess, off the UI thread.
		}
		return k, err
	}, func(res any, err error) {
		if err != nil {
			a.fail(capitalize(err.Error()) + ".")
			return
		}
		a.setKey(res.(*keystore.Key), "encrypted", path)
		a.settings.LastKeystore = path
		a.saveSettings()
	})
}

// saveEncrypted protects k with a new passphrase and calls done(path, err)
// when finished; done("", nil) means the user cancelled.
func (a *app) saveEncrypted(k *keystore.Key, dir string, done func(path string, err error)) {
	finish := func(path string, err error) {
		if done != nil {
			done(path, err)
		}
	}
	if k == nil {
		finish("", nil)
		return
	}
	path, ok := fileDialog(a.hwnd, true, "Save encrypted keystore", filterUTF16("IronVeil keystore (*.ivkey)", "*.ivkey"), "ivkey", "ironveil-owner"+keystore.FileExt, dir)
	if !ok {
		finish("", nil)
		return
	}
	if !strings.EqualFold(filepath.Ext(path), keystore.FileExt) {
		path += keystore.FileExt
	}
	if _, err := os.Stat(path); err == nil {
		a.warn("Choose a new file name: IronVeil Keygen never overwrites an existing keystore.")
		finish("", nil)
		return
	}
	pass, ok := askPassphrase(a, "Protect signing key", fmt.Sprintf("Choose a passphrase (at least %d characters). Without it the keystore cannot be opened, and there is no recovery.", keystore.MinPassphraseLen), true)
	if !ok {
		finish("", nil)
		return
	}
	kc := k.Clone() // The idle lock may wipe k while this runs in the background.
	if kc == nil {
		keystore.Wipe(pass)
		a.warn("The signing key was locked before it could be saved. Open it again and retry.")
		finish("", nil)
		return
	}
	a.runAsync("Encrypting the signing key…", func() (any, error) {
		defer keystore.Wipe(pass)
		defer kc.Wipe()
		blob, err := keystore.Seal(kc, pass, "IronVeil owner signing key", rand.Reader, time.Now())
		if err != nil {
			return nil, err
		}
		// Prove the file opens with the passphrase before writing it.
		check, err := keystore.Open(blob, pass)
		if err != nil {
			return nil, errors.New("self-check of the new keystore failed: " + err.Error())
		}
		check.Wipe()
		return nil, keystore.WriteFileSecure(path, blob)
	}, func(_ any, err error) {
		if err != nil {
			a.fail("Could not save the keystore: " + err.Error())
			finish("", err)
			return
		}
		a.settings.LastKeystore = path
		a.saveSettings()
		finish(path, nil)
	})
}

// adoptSaved switches the app to a freshly written keystore.
func (a *app) adoptSaved(path string) {
	if a.key != nil {
		a.keySource, a.keyPath = "encrypted", path
	}
	a.updateStatus()
	a.info("Encrypted keystore saved:\n" + path + "\n\nKeep a backup copy of this file and remember the passphrase; there is no recovery. Then move the unencrypted owner-kit key file to offline storage.")
}

func (a *app) newKeyPair() {
	if !a.ask("Create a NEW signing key pair?\n\nSites reject licenses and feeds signed with the new key until you:\n 1. put the new public key in includes/class-license.php (PUBLIC_KEY),\n 2. run php tools/build-checksums.php, and\n 3. release the updated plugin to all sites.\nOnce sites run that release, licenses issued with the old key stop working, so re-issue them with the new key.\n\nOnly do this if the old key was lost or exposed.") {
		return
	}
	k, err := keystore.Generate(rand.Reader)
	if err != nil {
		a.fail("Key generation failed: " + err.Error())
		return
	}
	a.saveEncrypted(k, "", func(path string, err error) {
		if path == "" || err != nil {
			k.Wipe() // Never keep an unsaved key: it could not be recovered later.
			return
		}
		a.setKey(k, "encrypted", path)
		pub := k.PublicBase64()
		_ = copyToClipboard(a.hwnd, pub)
		a.info("New key pair saved to:\n" + path + "\n\nNew public key (copied to the clipboard):\n" + pub + "\n\nPaste it into includes/class-license.php as PUBLIC_KEY, run php tools/build-checksums.php and release the plugin before issuing licenses with this key. Back up the keystore file and remember its passphrase.")
	})
}
