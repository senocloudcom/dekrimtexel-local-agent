// Package sonicwall polls SonicWall firewalls via REST API and reports
// to the dashboard via /v1/ingest/sonicwall.
package sonicwall

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		jar, _ := cookiejar.New(nil)
		newStates = append(newStates, deviceState{
			cfg:        d,
			username:   creds.Username,
			password:   creds.Password,
			httpClient: &http.Client{Transport: transport, Timeout: 30 * time.Second, Jar: jar},
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

	// Authenticate: login + start-management (required on SonicOS 7.x)
	if err := d.login(); err != nil {
		logger.Error("login failed", "err", err)
		return
	}
	if err := d.startManagement(); err != nil {
		logger.Warn("start-management failed (maybe already in mgmt)", "err", err)
	}
	// Always try to logout at the end to free the session slot
	defer d.logout()

	var deviceInfo map[string]interface{}
	vpnTunnels := []map[string]interface{}{}
	metrics := map[string]interface{}{}
	interfaces := []map[string]interface{}{}
	topThreats := []map[string]interface{}{}
	var haInfo map[string]interface{}

	// System status — correct path on SonicOS 7.3+ NSA
	if res := d.get("/reporting/status/system"); res != nil {
		deviceInfo = map[string]interface{}{
			"name":     firstNonEmpty(getNested(res, "firewall_name"), d.cfg.Name),
			"model":    getNested(res, "model"),
			"firmware": getNested(res, "firmware_version"),
			"serial":   getNested(res, "serial_number"),
			"uptime":   getNested(res, "up_time"),
		}
		// current_connections is a string like "Current: 6374" — extract number
		if s := getString(res, "current_connections"); s != "" {
			parts := strings.Split(s, ":")
			if len(parts) == 2 {
				metrics["connections"] = strings.TrimSpace(parts[1])
			}
		}
		if usage := getString(res, "connection_usage"); usage != "" {
			metrics["connection_usage"] = usage
		}
	}

	// CPU / memory usage (may or may not exist — try and ignore)
	if res := d.get("/reporting/status/cpu"); res != nil {
		metrics["cpu_percent"] = firstNonEmpty(getNested(res, "usage"), getNested(res, "cpu_usage"))
	}
	if res := d.get("/reporting/status/memory"); res != nil {
		metrics["ram_percent"] = firstNonEmpty(getNested(res, "usage"), getNested(res, "memory_usage"))
	}

	// VPN tunnels
	if res := d.get("/reporting/vpn/ipsec/active-tunnels"); res != nil {
		tunnels := extractList(res, "active_tunnels", "tunnels", "sa_statistics")
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

	// Interfaces — try multiple paths
	for _, path := range []string{"/reporting/status/interfaces", "/reporting/interfaces/statistics"} {
		res := d.get(path)
		if res == nil {
			continue
		}
		var totalIn, totalOut float64
		ifaces := extractList(res, "interfaces")
		if len(ifaces) == 0 {
			continue
		}
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
		break
	}

	// Threat / GAV / IPS / CFS — try multiple paths, ignore failures
	for _, ep := range []struct {
		path    string
		metric  string
		keys    []string
	}{
		{"/reporting/status/threat-prevention", "threats_blocked_today", []string{"blocked_today", "total_blocked"}},
		{"/reporting/status/gateway-anti-virus", "viruses_blocked", []string{"viruses_blocked", "blocked"}},
		{"/reporting/status/intrusion-prevention", "intrusions_blocked", []string{"intrusions_blocked", "blocked"}},
		{"/reporting/status/content-filter", "websites_blocked", []string{"websites_blocked", "blocked"}},
	} {
		if res := d.get(ep.path); res != nil {
			vals := make([]interface{}, len(ep.keys))
			for i, k := range ep.keys {
				vals[i] = getNested(res, k)
			}
			metrics[ep.metric] = firstNonEmpty(vals...)
		}
	}

	// DHCP leases (array response, niet object)
	dhcpLeases := []map[string]interface{}{}
	for _, lease := range d.getArray("/reporting/dhcp-server/ipv4/leases/status") {
		dhcpLeases = append(dhcpLeases, map[string]interface{}{
			"ip_address":    getString(lease, "ip_address"),
			"mac_address":   getString(lease, "mac_address"),
			"host_name":     getString(lease, "host_name"),
			"vendor":        getString(lease, "vendor"),
			"lease_expires": getString(lease, "lease_expires"),
			"type":          getString(lease, "type"),
		})
	}

	// HA status
	if res := d.get("/reporting/status/ha"); res != nil {
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
		"dhcp_leases": dhcpLeases,
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

func (d *deviceState) login() error {
	body := fmt.Sprintf(`{"user":%q,"password":%q,"override":true}`, d.username, d.password)
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
	if err := json.Unmarshal(b, &data); err != nil {
		return fmt.Errorf("parse login: %w", err)
	}
	if !isSuccess(data) {
		return fmt.Errorf("login rejected: %s", extractMessage(data))
	}
	return nil
}

func (d *deviceState) startManagement() error {
	req, _ := http.NewRequest("POST", d.url("/start-management"), nil)
	req.Header.Set("Accept", "application/json")
	res, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.ReadAll(res.Body)
	return nil
}

func (d *deviceState) logout() {
	req, _ := http.NewRequest("DELETE", d.url("/auth"), nil)
	res, err := d.httpClient.Do(req)
	if err == nil {
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
}

func (d *deviceState) get(path string) map[string]interface{} {
	req, err := http.NewRequest("GET", d.url(path), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	res, err := d.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return nil
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}
	// Reject error wrappers: {"status":{"success":false, ...}}
	if status, ok := data["status"].(map[string]interface{}); ok {
		if success, ok := status["success"].(bool); ok && !success {
			return nil
		}
	}
	return data
}

// getArray is voor endpoints die een JSON array teruggeven (bv DHCP leases)
func (d *deviceState) getArray(path string) []map[string]interface{} {
	req, err := http.NewRequest("GET", d.url(path), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	res, err := d.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return nil
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil
	}
	return arr
}

func isSuccess(data map[string]interface{}) bool {
	status, ok := data["status"].(map[string]interface{})
	if !ok {
		return false
	}
	success, _ := status["success"].(bool)
	return success
}

func extractMessage(data map[string]interface{}) string {
	status, ok := data["status"].(map[string]interface{})
	if !ok {
		return ""
	}
	info, ok := status["info"].([]interface{})
	if !ok || len(info) == 0 {
		return ""
	}
	first, ok := info[0].(map[string]interface{})
	if !ok {
		return ""
	}
	return getString(first, "message")
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
