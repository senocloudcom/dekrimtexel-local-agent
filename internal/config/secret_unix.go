//go:build !windows

package config

// Unix (Linux/macOS) secret storage — plain file with 0600 perms.
//
// This is a fallback. For production Linux we should switch to kernel
// keyring (via `keyctl`) but that adds a CGO dependency. The current file
// mode is already "owner-only" which matches the typical systemd service
// user isolation. Good enough for v0.1.

import (
	"fmt"
	"os"
)

func storeSecretPlatform(hexKey string) error {
	if err := os.WriteFile(SecretFile(), []byte(hexKey), 0600); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	return nil
}

func loadSecretPlatform() (string, error) {
	data, err := os.ReadFile(SecretFile())
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("secret not set — run 'local-agent set-secret --key <64-hex-chars>'")
		}
		return "", fmt.Errorf("read secret: %w", err)
	}
	return string(data), nil
}
