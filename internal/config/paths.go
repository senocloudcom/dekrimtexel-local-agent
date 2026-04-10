package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// Dir returns the platform-specific config directory.
//
// Windows: %PROGRAMDATA%\dekrimtexel-agent
// Linux:   /etc/dekrimtexel-agent
// macOS:   ~/Library/Application Support/dekrimtexel-agent (dev only)
func Dir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("PROGRAMDATA")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "dekrimtexel-agent")
	case "linux":
		return "/etc/dekrimtexel-agent"
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		return filepath.Join(home, "Library", "Application Support", "dekrimtexel-agent")
	default:
		return "./config"
	}
}

// ConfigFile returns the path to config.json.
func ConfigFile() string {
	return filepath.Join(Dir(), "config.json")
}

// SecretFile returns the path to the encrypted secret blob.
func SecretFile() string {
	return filepath.Join(Dir(), "secret.bin")
}

// LogFile returns the path to the main log file.
func LogFile() string {
	return filepath.Join(Dir(), "logs", "agent.log")
}

// EnsureDir creates the config dir if needed, with restrictive perms.
func EnsureDir() error {
	dir := Dir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	logsDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logsDir, 0700); err != nil {
		return err
	}
	return nil
}
