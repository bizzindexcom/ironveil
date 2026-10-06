package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const fixtureKey = "../license/testdata/test-only.key"
const fixturePub = "../license/testdata/test-only.pub"

var pass = []byte("correct horse battery staple")

func loadFixture(t *testing.T) *Key {
	t.Helper()
	data, err := os.ReadFile(fixtureKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePlain(data)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fastSeal uses the minimum accepted KDF cost to keep tests quick.
func fastSeal(t *testing.T, k *Key) []byte {
	t.Helper()
	b, err := sealWith(k, pass, "test", rand.Reader, time.Now(), minTime, minMemory, 1)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParsePlainOwnerKitFormat(t *testing.T) {
	k := loadFixture(t)
	pub, _ := os.ReadFile(fixturePub)
	if !k.Matches(string(pub)) || k.PublicBase64() != strings.TrimSpace(string(pub)) {
		t.Fatal("public key mismatch")
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(make([]byte, 63))} {
		if _, err := ParsePlain([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	// A 64-byte key whose public half was altered is detected.
	raw, _ := os.ReadFile(fixtureKey)
	sk, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	sk[40] ^= 1
	if _, err := ParsePlain([]byte(base64.StdEncoding.EncodeToString(sk))); err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("corruption not detected: %v", err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := loadFixture(t)
	blob := fastSeal(t, k)
	if !IsEncrypted(blob) || IsEncrypted([]byte("abc")) {
		t.Fatal("IsEncrypted wrong")
	}
	if strings.Contains(string(blob), base64.StdEncoding.EncodeToString(k.Private().Seed())) {
		t.Fatal("seed stored in clear")
	}
	k2, err := Open(blob, pass)
	if err != nil {
		t.Fatal(err)
	}
	if k2.PublicBase64() != k.PublicBase64() {
		t.Fatal("round trip changed the key")
	}
	if _, err := Open(blob, []byte("correct horse battery stapler")); err != ErrWrongPassphrase {
		t.Fatalf("wrong passphrase: %v", err)
	}
	k2.Wipe()
	if k2.Private() != nil || k2.Public() != nil {
		t.Fatal("wipe did not clear the key")
	}
}

func TestDefaultParamsSealOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("slow KDF")
	}
	k := loadFixture(t)
	start := time.Now()
	blob, err := Seal(k, pass, "", rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(blob, pass); err != nil {
		t.Fatal(err)
	}
	t.Logf("default Argon2id seal+open took %s", time.Since(start))
}

func TestTamperedHeaderRejected(t *testing.T) {
	k := loadFixture(t)
	other, _ := Generate(rand.Reader)
	blob := fastSeal(t, k)
	mutate := func(fn func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(blob, &m)
		fn(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := map[string][]byte{
		"weaker KDF time":    mutate(func(m map[string]any) { m["kdf"].(map[string]any)["time"] = 3 }),
		"swapped public key": mutate(func(m map[string]any) { m["public_key"] = other.PublicBase64() }),
		"changed salt": mutate(func(m map[string]any) {
			m["kdf"].(map[string]any)["salt"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
		}),
		"flipped ciphertext": mutate(func(m map[string]any) { c := []byte(m["ciphertext"].(string)); c[2] ^= 1; m["ciphertext"] = string(c) }),
		"memory bomb":        mutate(func(m map[string]any) { m["kdf"].(map[string]any)["memory_kib"] = 64 * 1024 * 1024 }),
		"trivial KDF":        mutate(func(m map[string]any) { m["kdf"].(map[string]any)["time"] = 1 }),
		"unknown field":      mutate(func(m map[string]any) { m["extra"] = 1 }),
		"other cipher":       mutate(func(m map[string]any) { m["cipher"] = "none" }),
		"truncated nonce":    mutate(func(m map[string]any) { m["nonce"] = "AAAA" }),
		"huge file":          append([]byte(`{"format":"ironveil-keystore",`), make([]byte, maxFileSize)...),
	}
	for name, data := range cases {
		if _, err := Open(data, pass); err == nil {
			t.Errorf("%s: tampered keystore opened", name)
		}
	}
}

func TestPassphrasePolicy(t *testing.T) {
	for _, bad := range []string{"short", "aaaaaaaaaaaaaaaa", " leading space pass", "trailing space pass ", string([]byte{0xff, 0xfe, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'})} {
		if CheckPassphrase([]byte(bad)) == nil {
			t.Errorf("accepted weak passphrase %q", bad)
		}
	}
	if CheckPassphrase([]byte("blue-tiger-river-77")) != nil {
		t.Error("rejected a good passphrase")
	}
}

func TestWriteFileSecure(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "owner"+FileExt)
	if err := WriteFileSecure(p, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileSecure(p, []byte("other")); err == nil {
		t.Fatal("overwrote an existing key file")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "secret" {
		t.Fatal("content changed")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("permissions %o", st.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %d entries", len(entries))
	}
}

func TestGenerate(t *testing.T) {
	a, _ := Generate(rand.Reader)
	b, _ := Generate(rand.Reader)
	if a.PublicBase64() == b.PublicBase64() || len(a.Private()) != 64 {
		t.Fatal("bad key generation")
	}
}

func FuzzOpen(f *testing.F) {
	f.Add([]byte(`{"format":"ironveil-keystore","version":1}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		_, _ = Open(data, []byte("x")) // Must never panic or hang.
		_, _ = ParsePlain(data)
	})
}

func TestCloneIsIndependent(t *testing.T) {
	k, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := k.Clone()
	k.Wipe()
	if c == nil || len(c.Private()) != ed25519.PrivateKeySize || c.PublicBase64() == "" {
		t.Fatal("clone must survive wiping the original")
	}
	if k.Clone() != nil {
		t.Fatal("cloning a wiped key must return nil")
	}
	var nilKey *Key
	if nilKey.Clone() != nil {
		t.Fatal("cloning nil must return nil")
	}
}
