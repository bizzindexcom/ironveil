package ledger

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendReadRevoke(t *testing.T) {
	p := filepath.Join(t.TempDir(), "issued.jsonl")
	created := 0
	protect := func(string) error { created++; return nil }
	for i, id := range []string{"aaaaaaaaaaaa", "bbbbbbbbbbbb"} {
		if err := Append(p, Entry{Event: "issued", ID: id, Name: "N", Type: "paid", Domains: []string{"x.com"}, Issued: 100, At: int64(100 + i), Key: "IVL1.x.y"}, protect); err != nil {
			t.Fatal(err)
		}
	}
	if created != 1 {
		t.Fatalf("protect called %d times, want once (on creation)", created)
	}
	if err := Append(p, Entry{Event: "revoked", ID: "aaaaaaaaaaaa"}, protect); err != nil {
		t.Fatal(err)
	}
	// A torn / garbage line (crash mid-write, manual edit) is skipped, not fatal.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("{\"event\":\"issued\",\"id\":\"cc\n")
	_, _ = f.WriteString(strings.Repeat("x", maxLineBytes+10) + "\n")
	_ = f.Close()
	// Records after a damaged line must still be read.
	if err := Append(p, Entry{Event: "issued", ID: "dddddddddddd", Name: "Late", At: 50}, protect); err != nil {
		t.Fatal(err)
	}
	got, skipped, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != "bbbbbbbbbbbb" || !got[1].Revoked || got[0].Revoked || got[2].ID != "dddddddddddd" || skipped != 2 {

		t.Fatalf("unexpected %+v skipped=%d", got, skipped)
	}
	if ids := RevokedIDs(got); len(ids) != 1 || ids[0] != "aaaaaaaaaaaa" {
		t.Fatalf("revoked ids %v", ids)
	}
	if err := Append(p, Entry{Event: "bogus", ID: "x"}, nil); err == nil {
		t.Fatal("invalid event accepted")
	}
}

func TestReadMissingFile(t *testing.T) {
	got, skipped, err := Read(filepath.Join(t.TempDir(), "none.jsonl"))
	if err != nil || got != nil || skipped != 0 {
		t.Fatal("missing ledger should be empty, not an error")
	}
}

func TestCSVFormulaInjection(t *testing.T) {
	out := CSV([]Entry{{ID: "id1", Name: "=HYPERLINK(\"http://evil\")", Type: "paid", Domains: []string{"a.com"}, Issued: 1}})
	if strings.Contains(out, `"=HYPERLINK`) || !strings.Contains(out, `"'=HYPERLINK(""http://evil"")"`) {
		t.Fatalf("formula not neutralised: %s", out)
	}
	if strings.Contains(out, "IVL1") {
		t.Fatal("CSV must not contain license keys")
	}
}

func TestAppendAfterTornLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "issued.jsonl")
	_ = Append(p, Entry{Event: "issued", ID: "aaaaaaaaaaaa", At: 1}, nil)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"event":"issued","id":"torn`) // Crash mid-write: no newline.
	_ = f.Close()
	if err := Append(p, Entry{Event: "issued", ID: "bbbbbbbbbbbb", At: 2}, nil); err != nil {
		t.Fatal(err)
	}
	got, skipped, _ := Read(p)
	if len(got) != 2 || skipped != 1 {
		t.Fatalf("record lost after torn line: %+v skipped=%d", got, skipped)
	}
}

// FuzzRead feeds arbitrary file contents to the reader and the CSV export,
// which must never panic and must neutralise spreadsheet formulas.
func FuzzRead(f *testing.F) {
	f.Add([]byte(`{"event":"issued","id":"abcd","name":"=cmd","domains":["a.com"],"issued":1}` + "\n" + `{"event":"revoked","id":"abcd"}`))
	f.Add([]byte("{\n}\n\x00\xff" + strings.Repeat("x", 20000)))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "issued.jsonl")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		entries, _, err := Read(p)
		if err != nil {
			return
		}
		_ = RevokedIDs(entries)
		rows, err := csv.NewReader(strings.NewReader(CSV(entries))).ReadAll()
		if err != nil {
			t.Fatalf("export is not valid CSV: %v", err)
		}
		for _, row := range rows {
			for _, cell := range row {
				if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
					t.Fatalf("unescaped formula cell %q", cell)
				}
			}
		}
	})
}
