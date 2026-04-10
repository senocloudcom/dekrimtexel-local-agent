// Package config handles the local agent config file (config.json) and the
// secret storage abstraction (OS-level encryption).
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the persistent local agent config.
// Stored as JSON in Dir()/config.json. Contains NO secrets — only identity info.
type Config struct {
	ServerURL string `json:"server_url"`  // https://ping.senocloud.com
	TenantID  string `json:"tenant_id"`   // "dekrim"
	APIKey    string `json:"api_key"`     // from POST /v1/pair
	Hostname  string `json:"hostname"`    // machine hostname at time of pair
	AgentType string `json:"agent_type"`  // usually "local"
}

// Load reads the config file from disk. Returns a descriptive error if
// the file does not exist (prompting the user to run `pair`).
func Load() (*Config, error) {
	path := ConfigFile()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config not found at %s — run 'local-agent pair --code ... --tenant ... --server ...'", path)
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ServerURL == "" || cfg.TenantID == "" || cfg.APIKey == "" {
		return nil, fmt.Errorf("config at %s is incomplete — please re-pair", path)
	}
	return &cfg, nil
}

// Save writes the config file with restrictive permissions.
func (c *Config) Save() error {
	if err := EnsureDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	path := ConfigFile()
	// 0600 — read/write owner only
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
