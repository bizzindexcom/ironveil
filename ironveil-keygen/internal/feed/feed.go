// Package feed signs IronVeil signature feeds (signatures.json) in the same
// format as tools/ironveil-sign.php, so revocations can be published without
// ever writing the owner key to disk unencrypted.
//
// The plugin replaces its whole feed state with every feed it installs, so a
// feed must always contain the full rule set plus every revoked license ID.
// Sign therefore takes the complete rules file and merges the revocations in.
package feed

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
)

// Limits mirror includes/class-signature-feed.php.
const (
	MaxDocBytes     = 2 * 1024 * 1024 // Signature_Feed::MAX_BYTES
	MaxRules        = 3000            // Signature_Feed::MAX_RULES
	MaxPattern      = 2000            // Signature_Feed::MAX_PATTERN
	MaxRevoked      = 10000           // revoked_licenses beyond this are ignored by the plugin
	MaxFilenames    = 1000
	DefaultLifetime = 90 * 24 * time.Hour // Same default as ironveil-sign.php.
)

// Sets are the rule groups the plugin reads.
var Sets = []string{"php", "js", "config"}

var (
	ruleIDRe  = regexp.MustCompile(`^[a-z0-9_]{3,40}$`)
	licIDRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)
	dangerRe  = regexp.MustCompile(`\(\*|\(\?C|\(\?\||\\[1-9gk]|\(\?P?<[a-zA-Z]|\(\?'|[\x00-\x08\x0e-\x1f]`)
	errNoRule = errors.New("rule must be a JSON object")
)

// Summary describes a signed feed for the confirmation dialog.
type Summary struct {
	Version int64
	Rules   map[string]int
	Revoked int
	Issued  int64
	Expires int64
}

// Document is the published signatures.json.
type Document struct {
	Version   int64  `json:"version"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Sign validates rulesJSON (the rules.json source file), merges revoked into
// "revoked_licenses", stamps format/issued/expires and returns the signed
// signatures.json document.
func Sign(rulesJSON []byte, revoked []string, priv ed25519.PrivateKey, now time.Time) ([]byte, Summary, error) {
	var sum Summary
	if len(priv) != ed25519.PrivateKeySize {
		return nil, sum, errors.New("no signing key")
	}
	if len(rulesJSON) > MaxDocBytes {
		return nil, sum, fmt.Errorf("the rules file is larger than %d bytes", MaxDocBytes)
	}
	m, err := decodeObject(rulesJSON)
	if err != nil {
		return nil, sum, fmt.Errorf("the rules file is not valid JSON: %w", err)
	}

	ver, ok := intValue(m["version"])
	if !ok || ver < 1 {
		return nil, sum, errors.New(`"version" must be a positive whole number, higher than the last feed you published`)
	}
	sum.Version = ver

	sum.Rules = map[string]int{}
	total := 0
	for _, set := range Sets {
		raw, present := m[set]
		if !present || raw == nil {
			continue
		}
		list, ok := raw.([]any)
		if !ok {
			return nil, sum, fmt.Errorf("%q must be a list of rules", set)
		}
		for i, r := range list {
			if err := ValidateRule(r); err != nil {
				return nil, sum, fmt.Errorf("rule %s[%d] (%s): %w; the plugin would reject it", set, i, ruleLabel(r), err)
			}
		}
		total += len(list)
		sum.Rules[set] = len(list)
	}
	if total > MaxRules {
		return nil, sum, fmt.Errorf("the feed has %d rules; the plugin reads at most %d", total, MaxRules)
	}

	if raw, present := m["filenames"]; present && raw != nil {
		list, ok := raw.([]any)
		if !ok {
			return nil, sum, errors.New(`"filenames" must be a list of file names`)
		}
		if len(list) > MaxFilenames {
			return nil, sum, fmt.Errorf(`"filenames" has %d entries; the plugin reads at most %d`, len(list), MaxFilenames)
		}
		for i, n := range list {
			if s, ok := n.(string); !ok || strings.TrimSpace(s) == "" {
				return nil, sum, fmt.Errorf(`"filenames"[%d] must be a non-empty string`, i)
			}
		}
	}

	ids, err := mergeRevoked(m["revoked_licenses"], revoked)
	if err != nil {
		return nil, sum, err
	}
	m["revoked_licenses"] = ids
	sum.Revoked = len(ids)

	sum.Issued = now.Unix()
	sum.Expires = now.Add(DefaultLifetime).Unix()
	if raw, present := m["expires"]; present && raw != nil {
		exp, ok := intValue(raw)
		if !ok || exp <= sum.Issued {
			return nil, sum, errors.New(`"expires" in the rules file must be a future Unix time; remove it to use the 90-day default`)
		}
		sum.Expires = exp
	}
	m["format"] = 1
	m["issued"] = sum.Issued
	m["expires"] = sum.Expires

	payload, err := encodeCompact(m)
	if err != nil {
		return nil, sum, err
	}
	doc, err := json.MarshalIndent(Document{
		Version:   ver,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}, "", "    ")
	if err != nil {
		return nil, sum, err
	}
	doc = append(doc, '\n')
	if len(doc) > MaxDocBytes {
		return nil, sum, fmt.Errorf("the signed feed is %d bytes; the plugin downloads at most %d", len(doc), MaxDocBytes)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	if _, err := Verify(doc, pub, now); err != nil {
		return nil, sum, fmt.Errorf("self-check of the signed feed failed: %w", err)
	}
	return doc, sum, nil
}

// Verify checks a signatures.json document the way the plugin does and
// returns its decoded payload.
func Verify(doc []byte, pub ed25519.PublicKey, now time.Time) (map[string]any, error) {
	if len(doc) > MaxDocBytes {
		return nil, errors.New("feed is too large")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("bad public key")
	}
	var d struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(doc, &d); err != nil || d.Payload == "" || d.Signature == "" {
		return nil, errors.New("feed is not in the expected format")
	}
	sig, err1 := base64.StdEncoding.DecodeString(d.Signature)
	raw, err2 := base64.StdEncoding.DecodeString(d.Payload)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("feed encoding is invalid")
	}
	if !ed25519.Verify(pub, raw, sig) {
		return nil, errors.New("feed signature is invalid")
	}
	m, err := decodeObject(raw)
	if err != nil {
		return nil, errors.New("feed payload is not valid JSON")
	}
	if f, ok := intValue(m["format"]); !ok || f != 1 {
		return nil, errors.New("unsupported feed format")
	}
	if v, ok := intValue(m["version"]); !ok || v < 1 {
		return nil, errors.New("unsupported feed version")
	}
	if exp, ok := intValue(m["expires"]); ok && exp != 0 && exp < now.Unix() {
		return nil, errors.New("feed has expired")
	}
	return m, nil
}

// ValidateRule applies the plugin's Signature_Feed::validate_rule checks that
// can be reproduced outside PHP (it additionally compiles the pattern with PCRE).
func ValidateRule(r any) error {
	obj, ok := r.(map[string]any)
	if !ok {
		return errNoRule
	}
	id, _ := obj["id"].(string)
	if !ruleIDRe.MatchString(id) {
		return errors.New(`"id" must be 3-40 characters of a-z, 0-9 and _`)
	}
	if sev, ok := intValue(obj["severity"]); !ok || sev < 1 || sev > 4 {
		return errors.New(`"severity" must be 1, 2, 3 or 4`)
	}
	if desc, _ := obj["description"].(string); strings.TrimSpace(desc) == "" {
		return errors.New(`"description" is required`)
	}
	pattern, _ := obj["pattern"].(string)
	switch {
	case pattern == "":
		return errors.New(`"pattern" is required`)
	case len(pattern) > MaxPattern:
		return fmt.Errorf(`"pattern" is longer than %d bytes`, MaxPattern)
	case dangerRe.MatchString(pattern):
		return errors.New(`"pattern" uses a construct IronVeil refuses (control verbs, callouts, back-references, named groups or control characters)`)
	case !balanced(pattern):
		return errors.New(`"pattern" has unbalanced parentheses or brackets`)
	}
	return nil
}

// balanced mirrors Signature_Feed::balanced: parentheses must balance at every
// point, ignoring escapes and character classes.
func balanced(p string) bool {
	depth, class := 0, false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' {
			i++
			continue
		}
		if class {
			if c == ']' {
				class = false
			}
			continue
		}
		switch c {
		case '[':
			class = true
			if i+1 < len(p) && p[i+1] == ']' {
				i++ // Literal ] right after [.
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && !class
}

func mergeRevoked(existing any, add []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	put := func(id string) error {
		if !licIDRe.MatchString(id) {
			return fmt.Errorf("%q is not a valid license ID", id)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
		return nil
	}
	if existing != nil {
		list, ok := existing.([]any)
		if !ok {
			return nil, errors.New(`"revoked_licenses" must be a list of license IDs`)
		}
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return nil, errors.New(`"revoked_licenses" must only contain license IDs`)
			}
			if err := put(s); err != nil {
				return nil, fmt.Errorf(`"revoked_licenses": %w`, err)
			}
		}
	}
	for _, id := range add {
		if err := put(id); err != nil {
			return nil, err
		}
	}
	if len(out) > MaxRevoked {
		return nil, fmt.Errorf("%d revoked licenses; the plugin reads at most %d", len(out), MaxRevoked)
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func decodeObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("top level must be a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON object")
	}
	return m, nil
}

func encodeCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// intValue accepts whole JSON numbers only.
func intValue(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

func ruleLabel(r any) string {
	if obj, ok := r.(map[string]any); ok {
		if id, ok := obj["id"].(string); ok && id != "" {
			if len(id) > 40 {
				id = id[:40]
			}
			return id
		}
	}
	return "?"
}
