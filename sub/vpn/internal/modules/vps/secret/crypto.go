// Package secret encrypts SSH credentials at rest (AES-256-GCM).
// Plaintext never appears in API JSON responses.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Box holds the derived AES key.
type Box struct {
	gcm cipher.AEAD
}

// NewBox derives a 32-byte key from env SSH_CRED_KEY or HMAC_SECRET / fallback.
func NewBox() (*Box, error) {
	raw := strings.TrimSpace(os.Getenv("SSH_CRED_KEY"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("HMAC_SECRET"))
	}
	if raw == "" {
		raw = "dev-ssh-cred-key-change-me"
	}
	sum := sha256.Sum256([]byte(raw))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{gcm: gcm}, nil
}

// Encrypt returns base64(nonce|ciphertext). Empty input → empty output.
func (b *Box) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if b == nil || b.gcm == nil {
		return "", errors.New("crypto box not initialized")
	}
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := b.gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt reverses Encrypt. Empty → empty.
func (b *Box) Decrypt(blob string) (string, error) {
	if blob == "" {
		return "", nil
	}
	if b == nil || b.gcm == nil {
		return "", errors.New("crypto box not initialized")
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext: %w", err)
	}
	ns := b.gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	plain, err := b.gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed: %w", err)
	}
	return string(plain), nil
}
