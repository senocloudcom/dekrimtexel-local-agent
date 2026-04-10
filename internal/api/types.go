package api

import "time"

// PairRequest is sent to POST /v1/pair
type PairRequest struct {
	Code     string `json:"code"`
	Hostname string `json:"hostname,omitempty"`
}

// PairResponse is returned by POST /v1/pair
type PairResponse struct {
	Status    string `json:"status"`
	APIKey    string `json:"api_key"`
	TenantID  string `json:"tenant_id"`
	AgentType string `json:"agent_type"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
}

// HeartbeatRequest is sent to POST /v1/ingest/heartbeat
type HeartbeatRequest struct {
	Hostname  string `json:"hostname"`
	AgentType string `json:"agent_type"`
	Version   string `json:"version"`
}

// RemoteConfig is returned by GET /v1/agent/config
type RemoteConfig struct {
	Agent       AgentInfo      `json:"agent"`
	Switches    []SwitchConfig `json:"switches"`
	PingTargets []PingTarget   `json:"ping_targets"`
	Syslog      SyslogConfig   `json:"syslog"`
	Crypto      CryptoInfo     `json:"crypto"`
}

type AgentInfo struct {
	ID        int             `json:"id"`
	Hostname  string          `json:"hostname"`
	AgentType string          `json:"agent_type"`
	Intervals AgentIntervals  `json:"intervals"`
	Modules   AgentModules    `json:"modules"`
}

type AgentIntervals struct {
	HeartbeatSeconds     int `json:"heartbeat_seconds"`
	TriggerPollSeconds   int `json:"trigger_poll_seconds"`
	ConfigRefetchSeconds int `json:"config_refetch_seconds"`
	ScanFullSeconds      int `json:"scan_full_seconds"`
	ScanPortsSeconds     int `json:"scan_ports_seconds"`
}

type AgentModules struct {
	Switch       bool `json:"switch"`
	Ping         bool `json:"ping"`
	Syslog       bool `json:"syslog"`
	WriteActions bool `json:"write_actions"`
}

// SwitchConfig is one switch as returned in the agent config
type SwitchConfig struct {
	ID                      int                     `json:"id"`
	Host                    string                  `json:"host"`
	Name                    string                  `json:"name"`
	Model                   string                  `json:"model"`
	Location                string                  `json:"location"`
	Role                    string                  `json:"role"`
	Commands                []string                `json:"commands"`
	SSHCredentialsEncrypted SSHCredentialsEncrypted `json:"ssh_credentials_encrypted"`
}

type SSHCredentialsEncrypted struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PingTarget struct {
	ID              int    `json:"id"`
	Host            string `json:"host"`
	Name            string `json:"name"`
	CheckType       string `json:"check_type"`
	TCPPort         *int   `json:"tcp_port"`
	IntervalSeconds int    `json:"interval_seconds"`
}

type SyslogConfig struct {
	Enabled       bool   `json:"enabled"`
	Port          int    `json:"port"`
	ListenAddress string `json:"listen_address"`
}

type CryptoInfo struct {
	Algorithm string `json:"algorithm"`
	Format    string `json:"format"`
	KeySource string `json:"key_source"`
}

// Trigger is a pending work item for the agent
type Trigger struct {
	Type                    string                   `json:"type"` // "scan" or "configure"
	ScanID                  string                   `json:"scan_id"`
	SwitchID                *int                     `json:"switch_id,omitempty"`
	Action                  string                   `json:"action,omitempty"`
	SwitchIDs               []int                    `json:"switch_ids,omitempty"`
	SSHCredentialsEncrypted *SSHCredentialsEncrypted `json:"ssh_credentials_encrypted,omitempty"`
	Params                  map[string]interface{}   `json:"params,omitempty"`
	IssuedAt                time.Time                `json:"issued_at"`
}

// TriggersResponse is returned by GET /v1/agent/triggers
type TriggersResponse struct {
	Triggers []Trigger `json:"triggers"`
}

// AckTriggerRequest is sent to POST /v1/agent/triggers/ack
type AckTriggerRequest struct {
	ScanID string `json:"scan_id"`
	Type   string `json:"type"`
	Result string `json:"result"` // "success" or "failure"
	Error  string `json:"error,omitempty"`
}

// NetworkIngestRequest is the shape for POST /v1/ingest/network
type NetworkIngestRequest struct {
	SwitchID        int                    `json:"switch_id"`
	SwitchName      string                 `json:"switch_name"`
	DataHash        string                 `json:"data_hash"`
	Changed         bool                   `json:"changed"`
	RawData         map[string]interface{} `json:"raw_data"`
	Severity        string                 `json:"severity"`
	ScanType        string                 `json:"scan_type"`
	FirmwareVersion string                 `json:"firmware_version,omitempty"`
	FirmwareChanged bool                   `json:"firmware_changed,omitempty"`
	PortStates      []PortState            `json:"port_states,omitempty"`
	Topology        []TopologyEntry        `json:"topology,omitempty"`
	ScanProgress    []ScanProgressStep     `json:"scan_progress,omitempty"`
}

type PortState struct {
	Port       string `json:"port"`
	Status     string `json:"status"`
	Speed      string `json:"speed,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
}

type TopologyEntry struct {
	LocalPort    string `json:"local_port"`
	RemoteName   string `json:"remote_name"`
	RemotePort   string `json:"remote_port"`
	LinkSpeed    string `json:"link_speed,omitempty"`
	Capabilities string `json:"capabilities,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
}

type ScanProgressStep struct {
	ScanID   string `json:"scan_id"`
	SwitchID *int   `json:"switch_id,omitempty"`
	Step     string `json:"step"`
	Detail   string `json:"detail"`
	Status   string `json:"status"` // "running", "done", "error"
}

// IngestResponse is the shape returned by most /v1/ingest/* endpoints
type IngestResponse struct {
	Status    string `json:"status"`
	Processed int    `json:"processed"`
	Error     string `json:"error,omitempty"`
}
