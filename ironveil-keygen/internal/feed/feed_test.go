package feed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// testKey loads the TEST-ONLY key pair shared with the license package.
func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	b, err := os.ReadFile("../license/testdata/test-only.key")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		t.Fatal("bad test key")
	}
	priv := ed25519.PrivateKey(raw)
	return priv, priv.Public().(ed25519.PublicKey)
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyPHPSignedFeed(t *testing.T) {
	_, pub := testKey(t)
	m, err := Verify(readFixture(t, "php-signatures.json"), pub, time.Now())
	if err != nil {
		t.Fatalf("feed signed by tools/ironveil-sign.php must verify: %v", err)
	}
	if ids, _ := m["revoked_licenses"].([]any); len(ids) != 1 || ids[0] != "AAAAtestID01" {
		t.Fatalf("unexpected revoked_licenses %v", m["revoked_licenses"])
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if _, err := Verify(readFixture(t, "php-signatures.json"), other, time.Now()); err == nil {
		t.Fatal("feed must not verify with another key")
	}
}

func TestSignMergesRevocationsAndKeepsRules(t *testing.T) {
	priv, pub := testKey(t)
	now := time.Unix(1790000000, 0)
	doc, sum, err := Sign(readFixture(t, "rules.json"), []string{"GecfZnCmD4XH", "AAAAtestID01"}, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Version != 1 || sum.Rules["php"] != 2 || sum.Rules["js"] != 1 || sum.Revoked != 2 || sum.Expires != 4102444800 {
		t.Fatalf("unexpected summary %+v", sum)
	}
	m, err := Verify(doc, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := m["revoked_licenses"].([]any)
	if len(ids) != 2 || ids[0] != "AAAAtestID01" || ids[1] != "GecfZnCmD4XH" {
		t.Fatalf("revocations must be merged, deduplicated and sorted: %v", ids)
	}
	if php, _ := m["php"].([]any); len(php) != 2 {
		t.Fatal("the full rule set must be kept: the plugin replaces its feed state on every update")
	}
	if names, _ := m["filenames"].([]any); len(names) != 2 {
		t.Fatal("filenames must be kept")
	}
	if issued, _ := intValue(m["issued"]); issued != now.Unix() {
		t.Fatal("issued must be stamped")
	}
	var d Document
	if err := json.Unmarshal(doc, &d); err != nil || d.Version != 1 {
		t.Fatalf("bad document: %v", err)
	}
	payload, _ := base64.StdEncoding.DecodeString(d.Payload)
	if strings.Contains(string(payload), `<`) || strings.Contains(string(payload), `\/`) {
		t.Fatal("payload must not HTML-escape or slash-escape")
	}
}

func TestSignDefaultExpiry(t *testing.T) {
	priv, _ := testKey(t)
	now := time.Unix(1790000000, 0)
	_, sum, err := Sign([]byte(`{"version":7}`), nil, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Expires != now.Add(DefaultLifetime).Unix() || sum.Revoked != 0 {
		t.Fatalf("unexpected summary %+v", sum)
	}
}

func TestSignRejects(t *testing.T) {
	priv, _ := testKey(t)
	now := time.Unix(1790000000, 0)
	rule := func(id, sev, desc, pattern string) string {
		return `{"version":2,"php":[{"id":` + id + `,"severity":` + sev + `,"description":` + desc + `,"pattern":` + pattern + `}]}`
	}
	cases := map[string]string{
		"not json":           `{"version":`,
		"trailing data":      `{"version":1} {}`,
		"array top level":    `[1]`,
		"no version":         `{"php":[]}`,
		"zero version":       `{"version":0}`,
		"fraction version":   `{"version":1.5}`,
		"string version":     `{"version":"3"}`,
		"set not a list":     `{"version":1,"php":{}}`,
		"rule not object":    `{"version":1,"php":["x"]}`,
		"bad id":             rule(`"Bad-ID"`, `3`, `"d"`, `"evil"`),
		"severity 5":         rule(`"abc"`, `5`, `"d"`, `"evil"`),
		"empty description":  rule(`"abc"`, `3`, `"  "`, `"evil"`),
		"empty pattern":      rule(`"abc"`, `3`, `"d"`, `""`),
		"control verb":       rule(`"abc"`, `3`, `"d"`, `"(*ACCEPT)x"`),
		"callout":            rule(`"abc"`, `3`, `"d"`, `"(?C1)x"`),
		"backreference":      rule(`"abc"`, `3`, `"d"`, `"(a)\\1"`),
		"named group":        rule(`"abc"`, `3`, `"d"`, `"(?<n>a)"`),
		"breakout":           rule(`"abc"`, `3`, `"d"`, `"a)|(b"`),
		"open class":         rule(`"abc"`, `3`, `"d"`, `"[abc"`),
		"control char":       rule(`"abc"`, `3`, `"d"`, `"a\u0001b"`),
		"long pattern":       rule(`"abc"`, `3`, `"d"`, `"`+strings.Repeat("a", MaxPattern+1)+`"`),
		"bad revoked id":     `{"version":1,"revoked_licenses":["no"]}`,
		"revoked not list":   `{"version":1,"revoked_licenses":"x"}`,
		"past expires":       `{"version":1,"expires":1}`,
		"filenames not list": `{"version":1,"filenames":"x"}`,
	}
	for name, in := range cases {
		if _, _, err := Sign([]byte(in), nil, priv, now); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, _, err := Sign([]byte(`{"version":1}`), []string{"bad id!"}, priv, now); err == nil {
		t.Error("an invalid revoked ID from the log must be rejected")
	}
	if _, _, err := Sign([]byte(`{"version":1}`), nil, nil, now); err == nil {
		t.Error("signing without a key must fail")
	}
}

func TestBalancedMirrorsPlugin(t *testing.T) {
	for p, want := range map[string]bool{
		`abc`: true, `(a|b)`: true, `\(`: true, `[(]`: true, `[]a]`: true, `[\]]`: true,
		`(`: false, `)`: false, `a)(b`: false, `[a`: false, `(?:a)(b)`: true,
	} {
		if got := balanced(p); got != want {
			t.Errorf("balanced(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestVerifyRejectsTamperingAndExpiry(t *testing.T) {
	priv, pub := testKey(t)
	now := time.Unix(1790000000, 0)
	doc, _, err := Sign([]byte(`{"version":3}`), []string{"GecfZnCmD4XH"}, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	_ = json.Unmarshal(doc, &d)
	payload, _ := base64.StdEncoding.DecodeString(d.Payload)
	d.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(payload), "GecfZnCmD4XH", "AAAAAAAAAAAA", 1)))
	forged, _ := json.Marshal(d)
	if _, err := Verify(forged, pub, now); err == nil {
		t.Fatal("altered payload must fail")
	}
	if _, err := Verify(doc, pub, now.Add(DefaultLifetime+time.Hour)); err == nil {
		t.Fatal("expired feed must fail")
	}
}

func FuzzSign(f *testing.F) {
	f.Add([]byte(`{"version":1,"php":[{"id":"abc","severity":3,"description":"d","pattern":"x"}]}`))
	f.Add([]byte(`{"version":9,"revoked_licenses":["AAAA"],"filenames":["a.php"]}`))
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Unix(1790000000, 0)
	f.Fuzz(func(t *testing.T, in []byte) {
		doc, _, err := Sign(in, nil, priv, now)
		if err != nil {
			return
		}
		if _, err := Verify(doc, pub, now); err != nil {
			t.Fatalf("a feed Sign accepted must verify: %v", err)
		}
	})
}
