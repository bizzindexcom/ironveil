// Package ledger keeps a local, append-only record of issued licenses so the
// owner can look keys up, resend them and revoke them later.
//
// The file is JSON Lines. Each line is either an issued license or a
// revocation marker. Lines are never rewritten, which makes the log robust
// against crashes (a torn last line is skipped) and easy to audit.
package ledger

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Entry is one issued license.
type Entry struct {
	Event   string   `json:"event"` // "issued" or "revoked".
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Type    string   `json:"type,omitempty"`
	Domains []string `json:"domains,omitempty"`
	Issued  int64    `json:"issued,omitempty"`
	Expires int64    `json:"expires,omitempty"`
	Key     string   `json:"key,omitempty"`
	At      int64    `json:"at"`
	Revoked bool     `json:"-"` // Derived when reading.
}

const (
	maxLineBytes = 16 * 1024
	maxFileBytes = 64 * 1024 * 1024
)

// Append adds one record to the ledger, creating the file if needed.
// create is called for a new file so the caller can restrict its permissions.
func Append(path string, e Entry, create func(string) error) error {
	if e.ID == "" || (e.Event != "issued" && e.Event != "revoked") {
		return errors.New("invalid ledger entry")
	}
	if e.At == 0 {
		e.At = time.Now().Unix()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(line) >= maxLineBytes {
		return errors.New("ledger entry too large")
	}
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- app-data path.
	if err != nil {
		return err
	}
	if os.IsNotExist(statErr) && create != nil {
		if err := create(path); err != nil {
			_ = f.Close()
			return fmt.Errorf("could not protect the ledger file: %w", err)
		}
	}
	if needsNewline(path) {
		line = append([]byte{'\n'}, line...) // Never glue a record onto a torn last line.
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Read returns issued licenses (newest first) with their revoked flag set.
// Malformed or oversized lines are skipped and counted.
func Read(path string) (entries []Entry, skipped int, err error) {
	f, err := os.Open(path) // #nosec G304 -- app-data path.
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxFileBytes {
		return nil, 0, errors.New("the ledger file is unexpectedly large")
	}
	revoked := map[string]int64{}
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		raw, tooLong, rerr := readLine(r)
		if rerr != nil {
			break
		}
		if tooLong {
			skipped++
			continue
		}
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		var e Entry
		if json.Unmarshal([]byte(line), &e) != nil || e.ID == "" {
			skipped++
			continue
		}
		switch e.Event {
		case "issued":
			entries = append(entries, e)
		case "revoked":
			revoked[e.ID] = e.At
		default:
			skipped++
		}
	}
	for i := range entries {
		if _, ok := revoked[entries[i].ID]; ok {
			entries[i].Revoked = true
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].At > entries[j].At })
	return entries, skipped, nil
}

// needsNewline reports whether a non-empty file does not end with '\n'.
func needsNewline(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- app-data path.
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return false
	}
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, st.Size()-1); err != nil {
		return false
	}
	return b[0] != '\n'
}

// readLine returns the next line; over-long lines are consumed and flagged so

// one damaged line never hides the records after it.
func readLine(r *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, false, err
		}
		if !tooLong {
			line = append(line, chunk...)
			if len(line) > maxLineBytes {
				tooLong, line = true, nil
			}
		}
		if !isPrefix {
			return line, tooLong, nil
		}
	}
}

// RevokedIDs lists every id marked revoked (for rebuilding the feed list).

func RevokedIDs(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		if e.Revoked {
			out = append(out, e.ID)
		}
	}
	return out
}

// CSV exports the ledger without the keys themselves.
func CSV(entries []Entry) string {
	var b strings.Builder
	b.WriteString("id,name,type,domains,issued_utc,expires_utc,revoked\r\n")
	for _, e := range entries {
		exp := "never"
		if e.Expires > 0 {
			exp = time.Unix(e.Expires, 0).UTC().Format("2006-01-02")
		}
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%t\r\n", csvCell(e.ID), csvCell(e.Name), csvCell(e.Type), csvCell(strings.Join(e.Domains, " ")),
			time.Unix(e.Issued, 0).UTC().Format("2006-01-02 15:04"), exp, e.Revoked)
	}
	return b.String()
}

// csvCell quotes a value and neutralises spreadsheet formula injection
// (cells starting with = + - @ are prefixed with an apostrophe).
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		s = "'" + s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
