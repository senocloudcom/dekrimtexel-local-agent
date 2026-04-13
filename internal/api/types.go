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
	Hostname                  string    `json:"hostname"`
	AgentType                 string    `json:"agent_type"`
	Version                   string    `json:"version"`
	LastPeriodicScanAt        string    `json:"last_periodic_scan_at,omitempty"`
	PeriodicScanRunningSince  string    `json:"periodic_scan_running_since,omitempty"`
	SyslogListenerActive      bool      `json:"syslog_listener_active,omitempty"`
	SyslogEventsReceived      int64     `json:"syslog_events_received,omitempty"`
}

// RemoteConfig is returned by GET /v1/agent/config
type RemoteConfig struct {
	Agent            AgentInfo         `json:"agent"`
	Switches         []SwitchConfig    `json:"switches"`
	PingTargets      []PingTarget      `json:"ping_targets"`
	SonicwallDevices []SonicwallDevice `json:"sonicwall_devices"`
	Syslog           SyslogConfig      `json:"syslog"`
	Crypto           CryptoInfo        `json:"crypto"`
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
	Sonicwall    bool `json:"sonicwall"`
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

// SonicwallDevice is a firewall to poll via REST API
type SonicwallDevice struct {
	ID                     int                     `json:"id"`
	Host                   string                  `json:"host"`
	Port                   int                     `json:"port"`
	Name                   string                  `json:"name"`
	PollInterval           int                     `json:"poll_interval"`
	CredentialsEncrypted   SSHCredentialsEncrypted `json:"credentials_encrypted"`
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

// AckTriggerRequest is sent to POST /v1/agent/triggers/ack (legacy backward compat)
type AckTriggerRequest struct {
	ScanID string `json:"scan_id"`
	Type   string `json:"type"`
	Result string `json:"result"` // "success" or "failure"
	Error  string `json:"error,omitempty"`
}

// Job is a single scan job claimed from the queue.
type Job struct {
	ScanID           string    `json:"scan_id"`
	Scope            string    `json:"scope"` // "all" or "single"
	TargetSwitchID   *int      `json:"target_switch_id,omitempty"`
	TargetSwitchName string    `json:"target_switch_name,omitempty"`
	QueuedAt         time.Time `json:"queued_at"`
}

// JobsResponse is returned by GET /v1/agent/jobs
type JobsResponse struct {
	Jobs []Job `json:"jobs"`
}

// FinishJobRequest is sent to POST /v1/agent/jobs/[scan_id]/finish
type FinishJobRequest struct {
	Result  string                 `json:"result"` // "success" | "partial" | "failure"
	Counts  map[string]int         `json:"counts,omitempty"`
	Summary string                 `json:"summary,omitempty"`
	Error   string                 `json:"error,omitempty"`
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
	MACTable        []MACEntry             `json:"mac_table,omitempty"`
	PoEStatus       []PoEPortStatus        `json:"poe_status,omitempty"`
	InterfaceStats  []InterfaceStat        `json:"interface_stats,omitempty"`
	PortSnapshots   []PortDeviceSnapshot   `json:"port_snapshots,omitempty"`
	ScanProgress    []ScanProgressStep     `json:"scan_progress,omitempty"`
}

// MACEntry is one row from `show mac address-table`
type MACEntry struct {
	VLAN       int    `json:"vlan"`
	MACAddress string `json:"mac_address"`
	Port       string `json:"port"`
	Type       string `json:"type,omitempty"` // dynamic, static, management
}

// PoEPortStatus is one row from `show power inline`
type PoEPortStatus struct {
	Port         string  `json:"port"`
	Enabled      bool    `json:"enabled"`
	Status       string  `json:"status,omitempty"` // on, off, searching, fault
	PowerWatts   float64 `json:"power_watts,omitempty"`
	Class        string  `json:"class,omitempty"`
	Priority     string  `json:"priority,omitempty"`
	DeviceType   string  `json:"device_type,omitempty"`
}

// InterfaceStat is per-port counter data from `show interfaces counters`
type InterfaceStat struct {
	Port           string `json:"port"`
	InOctets       int64  `json:"in_octets,omitempty"`
	OutOctets      int64  `json:"out_octets,omitempty"`
	InErrors       int64  `json:"in_errors,omitempty"`
	OutErrors      int64  `json:"out_errors,omitempty"`
	CRCErrors      int64  `json:"crc_errors,omitempty"`
	Collisions     int64  `json:"collisions,omitempty"`
	InDiscards     int64  `json:"in_discards,omitempty"`
	OutDiscards    int64  `json:"out_discards,omitempty"`
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

// PortDeviceSnapshot is one MAC+IP paired observation on a switch port
type PortDeviceSnapshot struct {
	Port       string `json:"port"`
	MACAddress string `json:"mac_address"`
	IPAddress  string `json:"ip_address,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
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

// SyslogEvent is one parsed syslog message ready to be sent to the dashboard.
// source_ip is filled by the listener from the UDP packet, not by the parser.
type SyslogEvent struct {
	SourceIP      string    `json:"source_ip"`
	SwitchID      *int      `json:"switch_id,omitempty"`
	SwitchName    string    `json:"switch_name,omitempty"`
	Facility      string    `json:"facility,omitempty"`
	Severity      string    `json:"severity"`
	SeverityLevel int       `json:"severity_level"`
	Mnemonic      string    `json:"mnemonic,omitempty"`
	Interface     string    `json:"interface,omitempty"`
	Message       string    `json:"message"`
	RawMessage    string    `json:"raw_message"`
	Timestamp     time.Time `json:"timestamp"`
}

// SyslogIngestRequest is the shape for POST /v1/ingest/syslog
type SyslogIngestRequest struct {
	Events []SyslogEvent `json:"events"`
}
