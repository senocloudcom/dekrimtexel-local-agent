// Package sonicwall polls SonicWall firewalls via REST API and reports
// to the dashboard via /v1/ingest/sonicwall.
package sonicwall

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/switches"
)

// Poller polls one or more SonicWall firewalls.
type Poller struct {
	Client    *api.Client
	SecretKey string
	devices   []deviceState
}

type deviceState struct {
	cfg         api.SonicwallDevice
	username    string
	password    string
	authToken   string
	httpClient  *http.Client
}

// NewPoller creates a new SonicWall poller.
func NewPoller(client *api.Client, secretKey string) *Poller {
	return &Poller{Client: client, SecretKey: secretKey}
}

// UpdateDevices replaces the device list (called on config refetch).
func (p *Poller) UpdateDevices(devices []api.SonicwallDevice) error {
	newStates := make([]deviceState, 0, len(devices))
	for _, d := range devices {
		creds, err := switches.DecryptCredentials(p.SecretKey, d.CredentialsEncrypted)
		if err != nil {
			slog.Error("sonicwall decrypt failed", "host", d.Host, "err", err)
			continue
		}
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // SonicWall gebruikt vaak self-signed
		}
		newStates = append(newStates, deviceState{
			cfg:        d,
			username:   creds.Username,
			password:   creds.Password,
			httpClient: &http.Client{Transport: transport, Timeout: 15 * time.Second},
		})
	}
	p.devices = newStates
	slog.Info("sonicwall devices loaded", "count", len(newStates))
	return nil
}

// Run starts polling each device on its interval.
func (p *Poller) Run(ctx context.Context) error {
	slog.Info("sonicwall poller started")

	// Poll all devices immediately, then on their own interval
	for i := range p.devices {
		go p.pollLoop(ctx, &p.devices[i])
	}

	<-ctx.Done()
	return nil
}

func (p *Poller) pollLoop(ctx context.Context, d *deviceState) {
	interval := time.Duration(d.cfg.PollInterval) * time.Second
	if interval < 60*time.Second {
		interval = 300 * time.Second
	}

	// Poll once immediately
	p.pollDevice(d)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollDevice(d)
		}
	}
}

func (p *Poller) pollDevice(d *deviceState) {
	logger := slog.With("sonicwall", d.cfg.Name, "host", d.cfg.Host)

	// Authenticate (try to get token)
	_ = d.authenticate()

	var deviceInfo map[string]interface{}
	vpnTunnels := []map[string]interface{}{}
	metrics := map[string]interface{}{}
	interfaces := []map[string]interface{}{}
	topThreats := []map[string]interface{}{}
	var haInfo map[string]interface{}

	// System status
	if res := d.get("/reporting/system/status"); res != nil {
		deviceInfo = map[string]interface{}{
			"name":     d.cfg.Name,
			"model":    firstNonEmpty(getNested(res, "firmware", "model"), getNested(res, "model")),
			"firmware": firstNonEmpty(getNested(res, "firmware", "version"), getNested(res, "firmware_version")),
			"serial":   getNested(res, "serial_number"),
			"uptime":   getNested(res, "uptime_seconds", "uptime"),
		}
	}

	// Performance
	if res := d.get("/reporting/system/resource"); res != nil {
		metrics["cpu_percent"] = firstNonEmpty(getNested(res, "cpu", "usage"), getNested(res, "cpu_usage"))
		metrics["ram_percent"] = firstNonEmpty(getNested(res, "memory", "usage"), getNested(res, "memory_usage"))
	}

	// Connections
	if res := d.get("/reporting/current-connection-count"); res != nil {
		metrics["connections"] = firstNonEmpty(getNested(res, "count"), getNested(res, "current_connections"))
	}

	// VPN tunnels
	if res := d.get("/reporting/vpn/sa-statistics"); res != nil {
		tunnels := extractList(res, "sa_statistics", "tunnels")
		for _, t := range tunnels {
			status := "inactive"
			if getBool(t, "active") || getString(t, "status") == "active" {
				status = "active"
			}
			vpnTunnels = append(vpnTunnels, map[string]interface{}{
				"name":      firstNonEmpty(getNested(t, "name"), getNested(t, "policy_name"), fmt.Sprintf("%s", getNested(t, "peer_gateway"))),
				"peer_ip":   firstNonEmpty(getNested(t, "peer_gateway"), getNested(t, "peer_ip")),
				"status":    status,
				"bytes_in":  firstNonEmpty(getNested(t, "bytes_received"), getNested(t, "rx_bytes")),
				"bytes_out": firstNonEmpty(getNested(t, "bytes_transmitted"), getNested(t, "tx_bytes")),
				"uptime":    firstNonEmpty(getNested(t, "tunnel_uptime"), getNested(t, "uptime")),
			})
		}
	}

	// Interfaces
	if res := d.get("/reporting/interfaces/statistics"); res != nil {
		var totalIn, totalOut float64
		ifaces := extractList(res, "interfaces")
		for _, iface := range ifaces {
			rxKbps := getFloat(iface, "rx_rate_kbps")
			txKbps := getFloat(iface, "tx_rate_kbps")
			interfaces = append(interfaces, map[string]interface{}{
				"name":    getString(iface, "name"),
				"rx_mbps": round1(rxKbps / 1024),
				"tx_mbps": round1(txKbps / 1024),
				"status":  firstNonEmpty(getNested(iface, "status"), getNested(iface, "link_status")),
				"ip":      firstNonEmpty(getNested(iface, "ip_address"), getNested(iface, "ip")),
			})
			name := getString(iface, "name")
			zone := getString(iface, "zone")
			if name == "X1" || name == "WAN" || zone == "WAN" {
				totalIn += rxKbps
				totalOut += txKbps
			}
		}
		metrics["bandwidth"] = map[string]interface{}{
			"in_mbps":  round1(totalIn / 1024),
			"out_mbps": round1(totalOut / 1024),
		}
	}

	// Threat prevention
	if res := d.get("/reporting/threat-prevention/summary"); res != nil {
		metrics["threats_blocked_today"] = firstNonEmpty(
			getNested(res, "blocked_today"), getNested(res, "total_blocked"),
			getNested(res, "intrusions_prevented"))
	}

	// Top threats (NSA 3700)
	if res := d.get("/reporting/threats/top"); res != nil {
		threats := extractList(res, "threats")
		for i, t := range threats {
			if i >= 10 {
				break
			}
			topThreats = append(topThreats, map[string]interface{}{
				"name":     firstNonEmpty(getNested(t, "name"), getNested(t, "threat_name")),
				"count":    firstNonEmpty(getNested(t, "count"), getNested(t, "hits")),
				"category": getString(t, "category"),
			})
		}
	}

	// GAV / IPS / Content Filter
	if res := d.get("/reporting/security-services/gateway-anti-virus"); res != nil {
		metrics["viruses_blocked"] = firstNonEmpty(getNested(res, "viruses_blocked"), getNested(res, "blocked"))
	}
	if res := d.get("/reporting/security-services/intrusion-prevention"); res != nil {
		metrics["intrusions_blocked"] = firstNonEmpty(getNested(res, "intrusions_blocked"), getNested(res, "blocked"))
	}
	if res := d.get("/reporting/security-services/content-filtering"); res != nil {
		metrics["websites_blocked"] = firstNonEmpty(getNested(res, "websites_blocked"), getNested(res, "blocked"))
	}

	// HA status
	if res := d.get("/reporting/high-availability/status"); res != nil {
		if state := getString(res, "state"); state != "" {
			haInfo = map[string]interface{}{
				"state":       state,
				"role":        getString(res, "role"),
				"peer_status": getString(res, "peer_status"),
				"last_sync":   getString(res, "last_sync"),
			}
		}
	}

	// Post to dashboard
	payload := map[string]interface{}{
		"host":        d.cfg.Host,
		"name":        d.cfg.Name,
		"device_info": deviceInfo,
		"vpn_tunnels": vpnTunnels,
		"interfaces":  interfaces,
		"top_threats": topThreats,
		"ha_info":     haInfo,
		"metrics":     metrics,
	}

	if err := p.Client.IngestSonicwall(payload); err != nil {
		logger.Error("ingest failed", "err", err)
		return
	}

	activeTunnels := 0
	for _, t := range vpnTunnels {
		if t["status"] == "active" {
			activeTunnels++
		}
	}
	logger.Info("reported", "tunnels", fmt.Sprintf("%d/%d", activeTunnels, len(vpnTunnels)))
}

// --- HTTP helpers ---

func (d *deviceState) url(path string) string {
	port := d.cfg.Port
	if port == 0 {
		port = 443
	}
	return fmt.Sprintf("https://%s:%d/api/sonicos%s", d.cfg.Host, port, path)
}

func (d *deviceState) authenticate() error {
	body := fmt.Sprintf(`{"user":%q,"password":%q}`, d.username, d.password)
	req, _ := http.NewRequest("POST", d.url("/auth"), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err == nil {
		if tok, ok := data["token"].(string); ok {
			d.authToken = tok
		}
	}
	return nil
}

func (d *deviceState) get(path string) map[string]interface{} {
	req, err := http.NewRequest("GET", d.url(path), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	if d.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+d.authToken)
	} else {
		auth := base64.StdEncoding.EncodeToString([]byte(d.username + ":" + d.password))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	res, err := d.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}
	return data
}

// --- JSON helpers ---

func getNested(m map[string]interface{}, keys ...string) interface{} {
	var cur interface{} = m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getFloat(m map[string]interface{}, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}

func firstNonEmpty(vals ...interface{}) interface{} {
	for _, v := range vals {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		return v
	}
	return nil
}

func extractList(m map[string]interface{}, keys ...string) []map[string]interface{} {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		if list, ok := v.([]interface{}); ok {
			out := make([]map[string]interface{}, 0, len(list))
			for _, item := range list {
				if mm, ok := item.(map[string]interface{}); ok {
					out = append(out, mm)
				}
			}
			return out
		}
		if mm, ok := v.(map[string]interface{}); ok {
			return []map[string]interface{}{mm}
		}
	}
	return nil
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
