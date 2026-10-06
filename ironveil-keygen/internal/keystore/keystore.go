// Package keystore loads and protects the IronVeil owner signing key.
//
// Two on-disk formats are supported:
//
//   - Plain key file (owner kit "ironveil-owner-private.key"): base64 of the
//     64-byte libsodium/Go Ed25519 secret key (32-byte seed || 32-byte public key).
//     Read-only: the app imports it and recommends replacing it with an
//     encrypted keystore.
//
//   - Encrypted keystore (*.ivkey): JSON with the 32-byte seed sealed by
//     XChaCha20-Poly1305 under a key derived from a passphrase with Argon2id.
//     Every header field (KDF parameters, salt, public key) is bound into the
//     AEAD as associated data, so tampering with any of them makes decryption
//     fail instead of silently weakening the file.
package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Format identifiers.
const (
	FormatName    = "ironveil-keystore"
	FormatVersion = 1
	FileExt       = ".ivkey"
)

// KDF parameters for new keystores (OWASP 2024+ Argon2id guidance, tuned for a
// desktop: ~0.5 s and 256 MiB).
const (
	DefaultTime    = 4
	DefaultMemory  = 256 * 1024 // KiB
	DefaultThreads = 4
	saltLen        = 32

	// Bounds accepted when opening a file: a tampered file can neither make
	// the KDF trivially weak nor exhaust memory/CPU.
	minTime, maxTime       = 2, 20
	minMemory, maxMemory   = 64 * 1024, 2 * 1024 * 1024
	minThreads, maxThreads = 1, 16

	// MinPassphraseLen is the minimum passphrase length in characters.
	MinPassphraseLen = 12
	maxFileSize      = 64 * 1024
)

// Errors returned to the UI.
var (
	ErrWrongPassphrase = errors.New("wrong passphrase, or the keystore file was altered")
	ErrNotKeystore     = errors.New("this is not an IronVeil keystore or key file")
)

type kdfParams struct {
	Name      string `json:"name"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      string `json:"salt"`
}

type fileV1 struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	KDF        kdfParams `json:"kdf"`
	Cipher     string    `json:"cipher"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	PublicKey  string    `json:"public_key"`
	Created    string    `json:"created"`
	Comment    string    `json:"comment,omitempty"`
}

// aad binds every security-relevant header field to the ciphertext.
func (f *fileV1) aad() []byte {
	return []byte(fmt.Sprintf("%s|%d|%s|%d|%d|%d|%s|%s|%s", f.Format, f.Version, f.KDF.Name, f.KDF.Time, f.KDF.MemoryKiB, f.KDF.Threads, f.KDF.Salt, f.Cipher, f.PublicKey))
}

// Key is an unlocked signing key. Call Wipe when done.
type Key struct {
	priv ed25519.PrivateKey
}

// Private returns the key for signing. It is nil after Wipe.
func (k *Key) Private() ed25519.PrivateKey {
	if k == nil {
		return nil
	}
	return k.priv
}

// Public returns the public half.
func (k *Key) Public() ed25519.PublicKey {
	if k == nil || len(k.priv) != ed25519.PrivateKeySize {
		return nil
	}
	return k.priv.Public().(ed25519.PublicKey)
}

// PublicBase64 is the public key in the plugin's PUBLIC_KEY format.
func (k *Key) PublicBase64() string { return base64.StdEncoding.EncodeToString(k.Public()) }

// Matches reports whether this key's public half equals the given base64 key.
func (k *Key) Matches(pubB64 string) bool {
	want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	return err == nil && len(want) == ed25519.PublicKeySize && subtle.ConstantTimeCompare(want, k.Public()) == 1
}

// Wipe overwrites the private key in memory (best effort in a garbage-collected runtime).
func (k *Key) Wipe() {
	if k != nil {
		Wipe(k.priv)
		k.priv = nil
	}
}

// Clone returns an independent copy of the key (nil if k is nil or wiped),
// so background work never reads memory that the UI may wipe on lock.
func (k *Key) Clone() *Key {
	if k == nil || len(k.priv) != ed25519.PrivateKeySize {
		return nil
	}
	return &Key{priv: append(ed25519.PrivateKey(nil), k.priv...)}
}

// Wipe zeroes a byte slice.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Generate creates a brand-new key pair.
func Generate(rnd io.Reader) (*Key, error) {
	_, priv, err := ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv}, nil
}

// fromSeed builds a key and checks it against an expected public key.
func fromSeed(seed []byte, wantPub []byte) (*Key, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrNotKeystore
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if wantPub != nil && subtle.ConstantTimeCompare(priv[32:], wantPub) != 1 {
		Wipe(priv)
		return nil, errors.New("the key file is corrupted: its public half does not belong to its private half")
	}
	return &Key{priv: priv}, nil
}

// ParsePlain reads the owner-kit format (base64 of seed||public).
func ParsePlain(data []byte) (*Key, error) {
	text := bytes.TrimSpace(data)
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	n, err := base64.StdEncoding.Decode(raw, text)
	defer Wipe(raw)
	if err != nil || n != ed25519.PrivateKeySize {
		return nil, ErrNotKeystore
	}
	return fromSeed(raw[:32], raw[32:64])
}

// IsEncrypted reports whether data looks like an encrypted keystore.
func IsEncrypted(data []byte) bool {
	t := bytes.TrimSpace(data)
	return len(t) > 0 && t[0] == '{' && bytes.Contains(t, []byte(`"`+FormatName+`"`))
}

// CheckPassphrase enforces the passphrase policy for new keystores.
func CheckPassphrase(pass []byte) error {
	if !utf8.Valid(pass) {
		return errors.New("the passphrase contains invalid characters")
	}
	if utf8.RuneCount(pass) < MinPassphraseLen {
		return fmt.Errorf("use a passphrase of at least %d characters (a few unrelated words work well)", MinPassphraseLen)
	}
	if len(bytes.TrimSpace(pass)) != len(pass) {
		return errors.New("the passphrase must not start or end with a space")
	}
	distinct := map[rune]bool{}
	for _, r := range string(pass) {
		distinct[r] = true
	}
	if len(distinct) < 5 {
		return errors.New("the passphrase is too repetitive")
	}
	return nil
}

// Seal encrypts the key under a passphrase.
func Seal(k *Key, pass []byte, comment string, rnd io.Reader, now time.Time) ([]byte, error) {
	return sealWith(k, pass, comment, rnd, now, DefaultTime, DefaultMemory, DefaultThreads)
}

func sealWith(k *Key, pass []byte, comment string, rnd io.Reader, now time.Time, t, m uint32, p uint8) ([]byte, error) {
	if k == nil || len(k.priv) != ed25519.PrivateKeySize {
		return nil, errors.New("no key to protect")
	}
	if err := CheckPassphrase(pass); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return nil, err
	}
	f := &fileV1{
		Format:    FormatName,
		Version:   FormatVersion,
		KDF:       kdfParams{Name: "argon2id", Time: t, MemoryKiB: m, Threads: p, Salt: base64.StdEncoding.EncodeToString(salt)},
		Cipher:    "xchacha20poly1305",
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		PublicKey: k.PublicBase64(),
		Created:   now.UTC().Format(time.RFC3339),
		Comment:   strings.TrimSpace(comment),
	}
	dk := argon2.IDKey(pass, salt, t, m, p, chacha20poly1305.KeySize)
	defer Wipe(dk)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}
	seed := k.priv.Seed()
	defer Wipe(seed)
	f.Ciphertext = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, seed, f.aad()))
	return json.MarshalIndent(f, "", "  ")
}

// Open decrypts an encrypted keystore.
func Open(data []byte, pass []byte) (*Key, error) {
	if len(data) > maxFileSize {
		return nil, ErrNotKeystore
	}
	var f fileV1
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.Format != FormatName {
		return nil, ErrNotKeystore
	}
	if f.Version != FormatVersion || f.KDF.Name != "argon2id" || f.Cipher != "xchacha20poly1305" {
		return nil, errors.New("unsupported keystore version; update IronVeil Keygen")
	}
	if f.KDF.Time < minTime || f.KDF.Time > maxTime || f.KDF.MemoryKiB < minMemory || f.KDF.MemoryKiB > maxMemory || f.KDF.Threads < minThreads || f.KDF.Threads > maxThreads {
		return nil, errors.New("the keystore has unsafe key-derivation settings (the file may have been tampered with)")
	}
	salt, err1 := base64.StdEncoding.DecodeString(f.KDF.Salt)
	nonce, err2 := base64.StdEncoding.DecodeString(f.Nonce)
	ct, err3 := base64.StdEncoding.DecodeString(f.Ciphertext)
	pub, err4 := base64.StdEncoding.DecodeString(f.PublicKey)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(salt) < 16 || len(nonce) != chacha20poly1305.NonceSizeX || len(pub) != ed25519.PublicKeySize {
		return nil, ErrNotKeystore
	}
	dk := argon2.IDKey(pass, salt, f.KDF.Time, f.KDF.MemoryKiB, f.KDF.Threads, chacha20poly1305.KeySize)
	defer Wipe(dk)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, ct, f.aad())
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	defer Wipe(seed)
	return fromSeed(seed, pub)
}

// ReadFile reads a key or keystore file with a size limit.
func ReadFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxFileSize {
		return nil, ErrNotKeystore
	}
	return os.ReadFile(path) // #nosec G304 -- path chosen by the user in a file dialog.
}

// WriteFileSecure writes data atomically to a new file that only the current
// user can read (owner-only ACL on Windows, mode 0600 elsewhere). It never
// overwrites an existing file.
func WriteFileSecure(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists; choose another name", filepath.Base(path))
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ivkeygen-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := restrictFile(tmpName); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("could not restrict file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, path); err != nil { // Fails if path appeared meanwhile (no overwrite race).
		if err2 := renameNoReplace(tmpName, path); err2 != nil {
			return err2
		}
	}
	ok = true
	_ = os.Remove(tmpName)
	return nil
}

// renameNoReplace is the fallback when hard links are unsupported (FAT/exFAT USB drives).
func renameNoReplace(from, to string) error {
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("%s already exists", filepath.Base(to))
	}
	return os.Rename(from, to)
}

// NewRandom is the production randomness source.
var NewRandom io.Reader = rand.Reader

// RestrictFile limits an existing file to the current user.
func RestrictFile(path string) error { return restrictFile(path) }
