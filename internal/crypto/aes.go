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
//
// Backwards compatibility: if the dashboard's AGENT_SECRET_KEY env var was not
// set when these values were stored, the dashboard's encrypt() function falls
// back to returning plain text. To handle that case, we detect missing colon
// or non-hex content and return the value as-is. This is intentionally lax
// because the alternative (failing all scans) is worse than running with the
// existing plain-text credentials. Once AGENT_SECRET_KEY is set on the
// dashboard side, the values should be re-encrypted properly.
func Decrypt(keyHex, payload string) (string, error) {
	if payload == "" {
		return "", nil
	}
	parts := strings.Split(payload, ":")
	if len(parts) != 2 {
		// Looks like plain text (no colon separator) — return as-is.
		// This is the fallback path when the dashboard encrypt() couldn't
		// actually encrypt because AGENT_SECRET_KEY was missing.
		return payload, nil
	}
	// Verify the iv part looks like hex; if not, treat as plain text containing a colon.
	if _, err := hex.DecodeString(parts[0]); err != nil {
		return payload, nil
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
