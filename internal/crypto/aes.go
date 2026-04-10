// Package crypto provides AES-256-GCM decryption that is wire-compatible
// with the dashboard's src/lib/crypto.js encrypt() function.
//
// Format (hex strings separated by ':'):
//
//	<iv_hex>:<ciphertext_plus_tag_hex>
//
// Where:
//   - iv_hex is 24 hex chars (12 bytes)
//   - ciphertext_plus_tag_hex is the ciphertext followed by the 16-byte GCM tag
//
// Key is a 32-byte (256-bit) AES key provided as 64 hex chars via config.LoadSecret().
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"strings"
)

// Decrypt returns the plaintext for a ciphertext encrypted by the dashboard.
// keyHex is the 64-char hex AES-256 master key.
// payload is of the form "iv:ciphertext+tag" (all hex).
func Decrypt(keyHex, payload string) (string, error) {
	if payload == "" {
		return "", nil
	}
	parts := strings.Split(payload, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid payload: expected 'iv:ciphertext' format")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid key hex: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(key))
	}

	iv, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid iv hex: %w", err)
	}
	if len(iv) != 12 {
		return "", fmt.Errorf("invalid iv length: expected 12 bytes, got %d", len(iv))
	}

	ctAndTag, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext hex: %w", err)
	}
	if len(ctAndTag) < 16 {
		return "", fmt.Errorf("ciphertext too short: %d bytes", len(ctAndTag))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	// AES-GCM in Go stdlib expects ciphertext || tag as a single input
	plaintext, err := gcm.Open(nil, iv, ctAndTag, nil)
	if err != nil {
		return "", fmt.Errorf("gcm decrypt: %w", err)
	}
	return string(plaintext), nil
}
