package config

// Secret storage abstraction. The platform-specific implementation is
// provided by secret_windows.go / secret_unix.go (via build tags).
//
// The agent secret key is a 64-hex-char AES-256-GCM master key used to decrypt
// switch credentials that are fetched via GET /v1/agent/config.

import (
	"encoding/hex"
	"fmt"
)

// StoreSecret saves the agent_secret_key to OS-level encrypted storage.
// The input must be a 64-character hex string (32 bytes).
func StoreSecret(hexKey string) error {
	if len(hexKey) != 64 {
		return fmt.Errorf("expected 64 hex chars, got %d", len(hexKey))
	}
	if _, err := hex.DecodeString(hexKey); err != nil {
		return fmt.Errorf("not valid hex: %w", err)
	}
	if err := EnsureDir(); err != nil {
		return err
	}
	return storeSecretPlatform(hexKey)
}

// LoadSecret retrieves the agent_secret_key from OS-level encrypted storage.
// Returns the raw 32-byte key as a hex string, or an error if not set.
func LoadSecret() (string, error) {
	return loadSecretPlatform()
}
