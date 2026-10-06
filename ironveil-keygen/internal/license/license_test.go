package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// testKey loads the TEST-ONLY key pair produced by the plugin's PHP tool.
func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile("testdata/test-only.key")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(sk) != ed25519.PrivateKeySize {
		t.Fatalf("bad fixture key: %v", err)
	}
	pubRaw, _ := os.ReadFile("testdata/test-only.pub")
	pk, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubRaw)))
	return ed25519.PrivateKey(sk), ed25519.PublicKey(pk)
}

func TestPHPIssuedKeyVerifies(t *testing.T) {
	_, pub := testKey(t)
	key, _ := os.ReadFile("testdata/php-license.txt")
	st := Verify(string(key), pub, "www.example.com", time.Now())
	if !st.Valid() {
		t.Fatalf("PHP-issued key rejected: %s", st.Reason)
	}
	if st.Payload.Name != "Fixture Customer – Ünïcode" || st.Payload.Type != TypePaid {
		t.Fatalf("payload mismatch: %+v", st.Payload)
	}
	if !Verify(string(key), pub, "a.shop.example", time.Now()).Valid() {
		t.Fatal("wildcard subdomain should be allowed")
	}
	if Verify(string(key), pub, "evil.example", time.Now()).Reason != ReasonDomain {
		t.Fatal("other domain should fail with domain")
	}
	if Verify(string(key), PluginPublicKeyBytes(), "", time.Now()).Reason != ReasonSignature {
		t.Fatal("test key must not verify against the real plugin key")
	}
}

func TestIssueRoundTripMatchesPHPFormat(t *testing.T) {
	priv, pub := testKey(t)
	now := time.Unix(1790000000, 0)
	if _, _, err := Issue(Request{Name: "  Acme <Ltd>  ", Type: TypePaid, Domains: []string{"Acme.com"}, Days: 365}, priv, rand.Reader, now); err == nil {
		t.Fatal("angle brackets in the name must be rejected")
	}
	key, p, err := Issue(Request{Name: "  Acme   Ltd  ", Type: TypePaid, Domains: []string{"https://WWW.Acme.com/shop", "acme.com", "*.acme.net"}, Days: 365}, priv, rand.Reader, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Acme Ltd" || len(p.Domains) != 3 || p.Domains[0] != "www.acme.com" || p.Expires != now.Unix()+365*86400 {
		t.Fatalf("unexpected payload %+v", p)
	}
	if !strings.HasPrefix(key, "IVL1.") || strings.ContainsAny(key, "+/= ") {
		t.Fatalf("bad key encoding: %s", key)
	}
	parts := strings.Split(key, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	// Same JSON layout as PHP json_encode(…, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE).
	if !bytes.HasPrefix(raw, []byte(`{"v":1,"id":"`)) || bytes.Contains(raw, []byte(`\/`)) || bytes.Contains(raw, []byte("\n")) {
		t.Fatalf("payload layout differs from PHP: %s", raw)
	}
	if len(p.ID) != 12 || !ValidID(p.ID) {
		t.Fatalf("id %q", p.ID)
	}
	if !Verify(key, pub, "acme.com", now).Valid() || !Verify(key, pub, "shop.acme.net", now).Valid() {
		t.Fatal("issued key does not verify")
	}
	if Verify(key, pub, "acme.com", now.Add(366*24*time.Hour)).Reason != ReasonExpired {
		t.Fatal("expiry not enforced")
	}
}

func TestTamperingDetected(t *testing.T) {
	priv, pub := testKey(t)
	key, _, err := Issue(Request{Name: "A", Type: TypePaid, Domains: []string{"a.com"}}, priv, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(key, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	forged := bytes.Replace(raw, []byte(`"a.com"`), []byte(`"*"`), 1)
	forgedKey := "IVL1." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]
	if st := Verify(forgedKey, pub, "b.com", time.Now()); st.Reason != ReasonSignature {
		t.Fatalf("forged domain accepted: %s", st.Reason)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 1
	if Verify(parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(sig), pub, "", time.Now()).Reason != ReasonSignature {
		t.Fatal("flipped signature bit accepted")
	}
	for _, bad := range []string{"", "IVL1", "IVL2." + parts[1] + "." + parts[2], "IVL1.!!." + parts[2], "IVL1." + parts[1], strings.Repeat("A", 5000)} {
		if Verify(bad, pub, "", time.Now()).Reason != ReasonFormat {
			t.Fatalf("garbage accepted: %.40q", bad)
		}
	}
	// Whitespace / line breaks from email clients are tolerated like in the plugin.
	if !Verify(" "+key[:30]+"\n"+key[30:]+"\r\n", pub, "a.com", time.Now()).Valid() {
		t.Fatal("whitespace not tolerated")
	}
}

func TestValidationRules(t *testing.T) {
	priv, _ := testKey(t)
	cases := []struct {
		req  Request
		want string
	}{
		{Request{Name: "", Type: TypePaid, Domains: []string{"a.com"}}, "name"},
		{Request{Name: "A", Type: "lifetime", Domains: []string{"a.com"}}, "type"},
		{Request{Name: "A", Type: TypePaid}, "domain"},
		{Request{Name: "A", Type: TypePaid, Domains: []string{"*"}}, "owner"},
		{Request{Name: "A", Type: TypeComplimentary, Domains: []string{"*"}}, "owner"},
		{Request{Name: "A", Type: TypePaid, Domains: []string{"exa mple.com"}}, ""}, // Splits into two hosts: fine.
		{Request{Name: "A", Type: TypePaid, Domains: []string{"ex_ample.com"}}, "valid"},
		{Request{Name: "A", Type: TypePaid, Domains: []string{"bücher.de"}}, "punycode"},
		{Request{Name: "A", Type: TypePaid, Domains: []string{"-bad.com"}}, "label"},
		{Request{Name: "A", Type: TypePaid, Domains: []string{"a.com"}, Days: -1}, "validity"},
		{Request{Name: "A", Type: TypePaid, Domains: []string{"a.com"}, Days: MaxDays + 1}, "validity"},
		{Request{Name: "A", Type: TypeOwner, Domains: []string{"*"}}, ""},
	}
	for i, c := range cases {
		_, _, err := Issue(c.req, priv, rand.Reader, time.Now())
		if c.want == "" && err != nil {
			t.Errorf("case %d: unexpected error %v", i, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("case %d: want error containing %q, got %v", i, c.want, err)
		}
	}
	many := make([]string, MaxDomains+1)
	for i := range many {
		many[i] = "d" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + "-" + string(rune('a'+i/26)) + ".com"
	}
	if _, _, err := Issue(Request{Name: "A", Type: TypePaid, Domains: many}, priv, rand.Reader, time.Now()); err == nil {
		t.Error("too many domains accepted")
	}
}

func TestNameTruncationKeepsUTF8(t *testing.T) {
	n, err := CleanName(strings.Repeat("é", 80) + "\x00\x07")
	if err != nil {
		t.Fatal(err)
	}
	if len(n) > MaxNameBytes || !utf8Valid(n) {
		t.Fatalf("bad truncation: %d bytes", len(n))
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }

func TestDomainAllowedMirrorsPlugin(t *testing.T) {
	cases := []struct {
		host    string
		domains []string
		want    bool
	}{
		{"example.com", []string{"example.com"}, true},
		{"www.example.com", []string{"example.com"}, true},
		{"example.com", []string{"www.example.com"}, true},
		{"shop.example.com", []string{"example.com"}, false},
		{"shop.example.com", []string{"*.example.com"}, true},
		{"example.com", []string{"*.example.com"}, true},
		{"badexample.com", []string{"*.example.com"}, false},
		{"anything.org", []string{"*"}, true},
		{"EXAMPLE.com.", []string{"example.com"}, true},
	}
	for _, c := range cases {
		if got := DomainAllowed(c.host, c.domains); got != c.want {
			t.Errorf("DomainAllowed(%q,%v)=%v want %v", c.host, c.domains, got, c.want)
		}
	}
}

func TestRevocationJSON(t *testing.T) {
	got := RevocationJSON([]string{"bbbbBBBB1234", " aaaa-AAAA_12 ", "bbbbBBBB1234", "x", "<script>"})
	want := `{"revoked_licenses":["aaaa-AAAA_12","bbbbBBBB1234"]}`
	if got != want {
		t.Fatalf("got %s", got)
	}
	var v map[string][]string
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatal(err)
	}
}

func TestPluginKeyConstant(t *testing.T) {
	if len(PluginPublicKeyBytes()) != ed25519.PublicKeySize {
		t.Fatal("bad plugin key")
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestIssueFailsClosedWithoutRandomness(t *testing.T) {
	priv, _ := testKey(t)
	if _, _, err := Issue(Request{Name: "A", Type: TypePaid, Domains: []string{"a.com"}}, priv, failReader{}, time.Now()); err == nil {
		t.Fatal("issued a key without a random id")
	}
	if _, _, err := Issue(Request{Name: "A", Type: TypePaid, Domains: []string{"a.com"}}, nil, rand.Reader, time.Now()); err == nil {
		t.Fatal("issued a key without a signing key")
	}
}

func FuzzVerify(f *testing.F) {
	priv, pub := func() (ed25519.PrivateKey, ed25519.PublicKey) {
		raw, _ := os.ReadFile("testdata/test-only.key")
		sk, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		k := ed25519.PrivateKey(sk)
		return k, k.Public().(ed25519.PublicKey)
	}()
	good, _, _ := Issue(Request{Name: "F", Type: TypePaid, Domains: []string{"f.com"}}, priv, rand.Reader, time.Now())
	f.Add(good)
	f.Add("IVL1.e30.AAAA")
	f.Add("IVL1." + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"id":"x","domains":["*"]}`)) + ".AA")
	f.Fuzz(func(t *testing.T, s string) {
		st := Verify(s, pub, "f.com", time.Now())
		if st.Valid() && !strings.HasPrefix(strings.Join(strings.Fields(s), ""), "IVL1.") {
			t.Fatal("non-IVL1 input accepted")
		}
	})
}
