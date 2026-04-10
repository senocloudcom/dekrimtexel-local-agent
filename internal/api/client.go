// Package api contains the HTTP client that talks to the Ping dashboard.
//
// All communication is outbound HTTPS, authenticated with X-Agent-Key and
// X-Tenant-Id headers (except for POST /v1/pair which bootstraps the keys).
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the HTTP client for the dashboard API.
type Client struct {
	BaseURL    string
	APIKey     string // empty during pair
	TenantID   string // empty during pair
	UserAgent  string
	HTTPClient *http.Client
}

// NewClient returns a new Client with sensible defaults.
func NewClient(baseURL, apiKey, tenantID, version string) *Client {
	return &Client{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		TenantID:  tenantID,
		UserAgent: "dekrimtexel-local-agent/" + version,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// do performs an HTTP request with auth headers and JSON encoding.
// If out is non-nil the response body is decoded into it.
func (c *Client) do(method, path string, in interface{}, out interface{}) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("X-Agent-Key", c.APIKey)
	}
	if c.TenantID != "" {
		req.Header.Set("X-Tenant-Id", c.TenantID)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, string(raw))
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unmarshal response: %w (body: %s)", err, string(raw))
		}
	}
	return nil
}

// Pair exchanges a pairing code for a permanent API key.
func (c *Client) Pair(code, hostname string) (*PairResponse, error) {
	var out PairResponse
	if err := c.do("POST", "/v1/pair", PairRequest{Code: code, Hostname: hostname}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat tells the dashboard this agent is alive.
func (c *Client) Heartbeat(hostname, agentType, version string) error {
	return c.do("POST", "/v1/ingest/heartbeat", HeartbeatRequest{
		Hostname:  hostname,
		AgentType: agentType,
		Version:   version,
	}, nil)
}

// GetConfig fetches the remote runtime config for this agent.
func (c *Client) GetConfig() (*RemoteConfig, error) {
	var out RemoteConfig
	if err := c.do("GET", "/v1/agent/config", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTriggers polls for pending scan/configure triggers.
func (c *Client) GetTriggers() ([]Trigger, error) {
	var out TriggersResponse
	if err := c.do("GET", "/v1/agent/triggers", nil, &out); err != nil {
		return nil, err
	}
	return out.Triggers, nil
}

// AckTrigger marks a trigger as processed.
func (c *Client) AckTrigger(scanID, triggerType, result, errMsg string) error {
	return c.do("POST", "/v1/agent/triggers/ack", AckTriggerRequest{
		ScanID: scanID,
		Type:   triggerType,
		Result: result,
		Error:  errMsg,
	}, nil)
}

// IngestNetwork sends switch scan data to the dashboard.
func (c *Client) IngestNetwork(data *NetworkIngestRequest) error {
	var out IngestResponse
	return c.do("POST", "/v1/ingest/network", data, &out)
}

// IngestScanProgress sends just scan progress updates (wraps IngestNetwork with minimal fields).
// Used for live progress updates during a scan so the dashboard modal can show steps in real time.
func (c *Client) IngestScanProgress(switchID int, switchName string, steps []ScanProgressStep) error {
	return c.IngestNetwork(&NetworkIngestRequest{
		SwitchID:     switchID,
		SwitchName:   switchName,
		DataHash:     "",
		Changed:      false,
		RawData:      nil,
		Severity:     "info",
		ScanType:     "progress",
		ScanProgress: steps,
	})
}
