// Package license creates, parses and verifies IronVeil Security license keys.
//
// The format is defined by the WordPress plugin (includes/class-license.php)
// and its PHP tool (tools/ironveil-license.php):
//
//	IVL1.<base64url(payload JSON)>.<base64url(Ed25519 signature of the payload bytes)>
//
//	payload = {"v":1,"id":"…","name":"…","type":"paid|complimentary|owner",
//	           "domains":["example.com","*.example.org"],"issued":<unix>,"expires":<unix|0>}
//
// Every rule the plugin applies when it accepts a key is mirrored here, so a key
// this package issues is accepted by the plugin, and Verify gives the same
// answer the plugin would.
package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Prefix is the key-format marker the plugin requires.
const Prefix = "IVL1"

// PluginPublicKey is the verification key built into IronVeil Security
// (License::PUBLIC_KEY in includes/class-license.php). Keys signed with any
// other private key are rejected by the plugin.
const PluginPublicKey = "40K0ro0Hol80wqZMB/m1TX1ic5e9tFs00JU2GB6Hrbg="

// Limits enforced by the plugin or chosen to stay well inside them.
const (
	MaxKeyLength = 4096 // The plugin rejects longer keys.
	MaxDomains   = 50
	MaxNameBytes = 100 // The plugin keeps the first 100 bytes of the name.
	MaxDays      = 36500
	idBytes      = 9 // 12 base64url characters, like the PHP tool.
)

// License types.
const (
	TypePaid          = "paid"
	TypeComplimentary = "complimentary"
	TypeOwner         = "owner"
)

// Types lists the valid license types in display order.
var Types = []string{TypePaid, TypeComplimentary, TypeOwner}

// Payload is the signed content of a key. Field order matches the PHP tool.
type Payload struct {
	V       int      `json:"v"`
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Domains []string `json:"domains"`
	Issued  int64    `json:"issued"`
	Expires int64    `json:"expires"`
}

// Request describes a license to issue.
type Request struct {
	Name    string
	Type    string
	Domains []string // Raw entries; normalised by Issue.
	Days    int      // 0 = never expires.
}

var (
	domainRe = regexp.MustCompile(`^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*$`)
	keyRe    = regexp.MustCompile(`^IVL1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)
)

// NormalizeDomain turns user input such as "https://WWW.Example.com:443/shop"
// into the bare host the plugin compares against ("www.example.com"), and
// validates it. "*" (any site) and "*.example.com" (domain + subdomains) are
// accepted.
func NormalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	if d == "*" {
		return d, nil
	}
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndex(d, "@"); i >= 0 {
		d = d[i+1:]
	}
	if i := strings.LastIndex(d, ":"); i >= 0 {
		d = d[:i] // Port.
	}
	d = strings.Trim(d, ".")
	if d == "" {
		return "", errors.New("empty domain")
	}
	for _, r := range d {
		if r > unicode.MaxASCII {
			return "", fmt.Errorf("%q contains non-ASCII characters: enter internationalised domains in punycode (xn--…)", raw)
		}
	}
	if len(d) > 253 {
		return "", fmt.Errorf("%q is too long", raw)
	}
	if !domainRe.MatchString(d) {
		return "", fmt.Errorf("%q is not a valid domain (use the bare host, e.g. example.com or *.example.com)", raw)
	}
	for _, label := range strings.Split(strings.TrimPrefix(d, "*."), ".") {
		if len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%q is not a valid domain (label %q)", raw, label)
		}
	}
	return d, nil
}

// ParseDomainList splits free text (lines, commas, spaces) into normalised,
// de-duplicated domains.
func ParseDomainList(text string) ([]string, error) {
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t'
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		d, err := NormalizeDomain(f)
		if err != nil {
			return nil, err
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("enter at least one domain")
	}
	if len(out) > MaxDomains {
		return nil, fmt.Errorf("too many domains (%d); the maximum is %d", len(out), MaxDomains)
	}
	return out, nil
}

// CleanName removes control characters and HTML brackets (the plugin strips
// tags) and limits the name to MaxNameBytes without splitting a character.
func CleanName(name string) (string, error) {
	var b strings.Builder
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r == utf8.RuneError:
			return "", errors.New("the customer name contains invalid characters")
		case unicode.IsControl(r):
			continue
		case r == '<' || r == '>':
			return "", errors.New("the customer name may not contain < or >")
		}
		b.WriteRune(r)
	}
	s := strings.Join(strings.Fields(b.String()), " ")
	for len(s) > MaxNameBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return strings.TrimSpace(s), nil
}

// ValidateRequest checks a request the way the PHP tool does and returns the
// normalised domains and name.
func ValidateRequest(req Request) (name string, domains []string, err error) {
	if name, err = CleanName(req.Name); err != nil {
		return "", nil, err
	}
	if name == "" {
		return "", nil, errors.New("enter the customer name")
	}
	switch req.Type {
	case TypePaid, TypeComplimentary, TypeOwner:
	default:
		return "", nil, fmt.Errorf("unknown license type %q", req.Type)
	}
	if domains, err = ParseDomainList(strings.Join(req.Domains, "\n")); err != nil {
		return "", nil, err
	}
	for _, d := range domains {
		if d == "*" && req.Type != TypeOwner {
			return "", nil, errors.New(`the "*" (any site) domain is only allowed for owner licenses`)
		}
	}
	if req.Days < 0 || req.Days > MaxDays {
		return "", nil, fmt.Errorf("validity must be between 0 (never expires) and %d days", MaxDays)
	}
	return name, domains, nil
}

// Issue validates the request and signs a new key. rnd supplies the license id
// (crypto/rand.Reader in production).
func Issue(req Request, priv ed25519.PrivateKey, rnd io.Reader, now time.Time) (string, Payload, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", Payload{}, errors.New("no valid signing key is loaded")
	}
	name, domains, err := ValidateRequest(req)
	if err != nil {
		return "", Payload{}, err
	}
	idRaw := make([]byte, idBytes)
	if _, err := io.ReadFull(rnd, idRaw); err != nil {
		return "", Payload{}, fmt.Errorf("random generator failed: %w", err)
	}
	p := Payload{
		V:       1,
		ID:      base64.RawURLEncoding.EncodeToString(idRaw),
		Name:    name,
		Type:    req.Type,
		Domains: domains,
		Issued:  now.Unix(),
	}
	if req.Days > 0 {
		p.Expires = now.Unix() + int64(req.Days)*86400
	}
	raw, err := marshal(p)
	if err != nil {
		return "", Payload{}, err
	}
	sig := ed25519.Sign(priv, raw)
	key := Prefix + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
	if len(key) > MaxKeyLength {
		return "", Payload{}, fmt.Errorf("the key would be %d characters; the plugin accepts at most %d (use fewer domains or a shorter name)", len(key), MaxKeyLength)
	}
	// Self-check with the public half of the signing key before handing it out.
	if st := Verify(key, priv.Public().(ed25519.PublicKey), "", now); st.Reason != ReasonOK && st.Reason != ReasonDomain {
		return "", Payload{}, fmt.Errorf("internal self-check failed: %s", st.Message())
	}
	return key, p, nil
}

// marshal encodes like PHP json_encode(…, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE).
func marshal(p Payload) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Verification outcomes (the plugin's reason codes).
const (
	ReasonOK        = "ok"
	ReasonFormat    = "format"
	ReasonSignature = "signature"
	ReasonExpired   = "expired"
	ReasonDomain    = "domain"
)

// Status is the result of Verify.
type Status struct {
	Reason  string
	Payload *Payload // Decoded payload when the format is valid (even if the signature is not).
}

// Valid reports whether the plugin would activate Pro with this key.
func (s Status) Valid() bool { return s.Reason == ReasonOK }

// Message is a human explanation of the status.
func (s Status) Message() string {
	switch s.Reason {
	case ReasonOK:
		return "Valid: the plugin will accept this key."
	case ReasonFormat:
		return "Not a valid IronVeil license key."
	case ReasonSignature:
		return "Signature check FAILED: this key was not signed with the plugin's key (forged, altered or signed with another key)."
	case ReasonExpired:
		return "Genuine, but expired."
	case ReasonDomain:
		return "Genuine, but not valid for this domain."
	}
	return s.Reason
}

// Verify checks a key like License::verify() in the plugin. host may be empty
// to skip the domain check.
func Verify(key string, pub ed25519.PublicKey, host string, now time.Time) Status {
	key = strings.Join(strings.Fields(key), "") // The plugin strips whitespace on activation.
	if len(key) > MaxKeyLength {
		return Status{Reason: ReasonFormat}
	}
	m := keyRe.FindStringSubmatch(key)
	if m == nil || len(pub) != ed25519.PublicKeySize {
		return Status{Reason: ReasonFormat}
	}
	raw, err1 := b64urlDecode(m[1])
	sig, err2 := b64urlDecode(m[2])
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		return Status{Reason: ReasonFormat}
	}
	p, perr := decodePayload(raw)
	if !ed25519.Verify(pub, raw, sig) {
		if perr != nil {
			return Status{Reason: ReasonSignature}
		}
		return Status{Reason: ReasonSignature, Payload: &p}
	}
	if perr != nil {
		return Status{Reason: ReasonFormat}
	}
	if p.Expires != 0 && p.Expires < now.Unix() {
		return Status{Reason: ReasonExpired, Payload: &p}
	}
	if host != "" && !DomainAllowed(host, p.Domains) {
		return Status{Reason: ReasonDomain, Payload: &p}
	}
	return Status{Reason: ReasonOK, Payload: &p}
}

// decodePayload applies the plugin's structural checks.
func decodePayload(raw []byte) (Payload, error) {
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&p); err != nil {
		return Payload{}, err
	}
	if p.V != 1 || p.ID == "" || len(p.Domains) == 0 {
		return Payload{}, errors.New("payload is missing required fields")
	}
	return p, nil
}

// b64urlDecode accepts base64url with or without padding (like the plugin).
func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// normalizeHost mirrors License::normalize_host().
func normalizeHost(h string) string {
	h = strings.ToLower(strings.Trim(h, " .\t\n"))
	return strings.TrimPrefix(h, "www.")
}

// DomainAllowed mirrors License::domain_allowed().
func DomainAllowed(host string, domains []string) bool {
	host = normalizeHost(host)
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "*":
			return true
		case strings.HasPrefix(d, "*."):
			base := normalizeHost(d[2:])
			if host == base || strings.HasSuffix(host, "."+base) {
				return true
			}
		case normalizeHost(d) == host:
			return true
		}
	}
	return false
}

// PluginPublicKeyBytes decodes PluginPublicKey.
func PluginPublicKeyBytes() ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(PluginPublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("license: invalid built-in public key")
	}
	return ed25519.PublicKey(b)
}

// RevocationJSON builds the snippet to paste into the signed signature feed
// (tools/feed-example.json) to revoke keys. Invalid ids are dropped.
func RevocationJSON(ids []string) string {
	seen := map[string]bool{}
	var clean []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if idRe.MatchString(id) && !seen[id] {
			seen[id] = true
			clean = append(clean, id)
		}
	}
	sort.Strings(clean)
	b, _ := json.Marshal(map[string][]string{"revoked_licenses": clean})
	return string(b)
}

// ValidID reports whether s looks like a license id.
func ValidID(s string) bool { return idRe.MatchString(s) }
