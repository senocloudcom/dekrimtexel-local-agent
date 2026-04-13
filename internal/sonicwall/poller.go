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
	"sync"
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
	cfg          api.SonicwallDevice
	username     string
	password     string
	httpClient   *http.Client
	sessionMu    sync.Mutex
	loggedIn     bool
	leaseCache   map[string]cachedLease // key = ip_address
	cacheMu      sync.Mutex
}

// cachedLease is the previous state for diff detection
type cachedLease struct {
	MAC           string
	HostName      string
	Vendor        string
	LeaseType     string
	LeaseExpires  string
	IssuedAt      time.Time
}

// NewPoller creates a new SonicWall poller.
func NewPoller(client *api.Client, secretKey string) *Poller {
	return &Poller{Client: client, SecretKey: secretKey}
}

// LookupMAC zoekt een MAC in de DHCP lease cache van alle devices.
// Returnt IP, hostname, vendor (lege strings als niet gevonden).
func (p *Poller) LookupMAC(mac string) (ip, hostname, vendor string) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return "", "", ""
	}
	for i := range p.devices {
		d := &p.devices[i]
		d.cacheMu.Lock()
		for ip2, lease := range d.leaseCache {
			if strings.ToLower(lease.MAC) == mac {
				d.cacheMu.Unlock()
				return ip2, lease.HostName, lease.Vendor
			}
		}
		d.cacheMu.Unlock()
	}
	return "", "", ""
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
			leaseCache: make(map[string]cachedLease),
		})
	}
	p.devices = newStates
	slog.Info("sonicwall devices loaded", "count", len(newStates))
	return nil
}

// Run starts polling each device with 2 tiers: fast (5s, DHCP only) + slow (PollInterval, everything).
func (p *Poller) Run(ctx context.Context) error {
	slog.Info("sonicwall poller started")

	for i := range p.devices {
		go p.slowLoop(ctx, &p.devices[i])
		go p.fastLoop(ctx, &p.devices[i])
		go p.keepAliveLoop(ctx, &p.devices[i])
	}

	<-ctx.Done()
	// Logout all devices
	for i := range p.devices {
		p.devices[i].logoutIfAny()
	}
	return nil
}

// slowLoop runs the full poll (system/cpu/vpn/etc) on PollInterval (default 300s).
func (p *Poller) slowLoop(ctx context.Context, d *deviceState) {
	interval := time.Duration(d.cfg.PollInterval) * time.Second
	if interval < 60*time.Second {
		interval = 300 * time.Second
	}
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

// fastLoop runs only the DHCP lease poll every 5 seconds for near-realtime events.
func (p *Poller) fastLoop(ctx context.Context, d *deviceState) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollDHCPFast(d)
		}
	}
}

// keepAliveLoop pings /version every 45 sec to keep the session alive (SonicOS inactivity = 60s).
func (p *Poller) keepAliveLoop(ctx context.Context, d *deviceState) {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.sessionMu.Lock()
			if d.loggedIn {
				_ = d.get("/version") // keeps session alive
			}
			d.sessionMu.Unlock()
		}
	}
}

// ensureSession zorgt dat er een geldige sessie is. Returned true bij success.
func (d *deviceState) ensureSession() bool {
	d.sessionMu.Lock()
	defer d.sessionMu.Unlock()
	if d.loggedIn {
		// Quick health check
		if res := d.get("/version"); res != nil {
			return true
		}
		d.loggedIn = false
	}
	if err := d.login(); err != nil {
		return false
	}
	_ = d.startManagement()
	d.loggedIn = true
	return true
}

func (d *deviceState) logoutIfAny() {
	d.sessionMu.Lock()
	defer d.sessionMu.Unlock()
	if d.loggedIn {
		d.logout()
		d.loggedIn = false
	}
}

// pollDHCPFast haalt alleen DHCP leases op en genereert events bij diffs.
func (p *Poller) pollDHCPFast(d *deviceState) {
	if !d.ensureSession() {
		return
	}

	leases := d.getArray("/reporting/dhcp-server/ipv4/leases/status")
	if leases == nil {
		return
	}

	now := time.Now()
	events := []map[string]interface{}{}
	seenIPs := make(map[string]bool)
	leaseList := []map[string]interface{}{}

	d.cacheMu.Lock()
	for _, lease := range leases {
		ip := getString(lease, "ip_address")
		if ip == "" {
			continue
		}
		seenIPs[ip] = true
		mac := getString(lease, "mac_address")
		host := getString(lease, "host_name")
		vendor := getString(lease, "vendor")
		ltype := getString(lease, "type")
		expires := getString(lease, "lease_expires")

		prev, existed := d.leaseCache[ip]
		var eventType string
		issuedAt := now

		switch {
		case !existed:
			eventType = "new"
		case prev.MAC != mac:
			// IP now belongs to different MAC — treat as new
			eventType = "new"
		case prev.LeaseExpires != expires:
			eventType = "renewal"
			issuedAt = prev.IssuedAt // keep original issue time
		default:
			// Nothing changed — just update cache
			issuedAt = prev.IssuedAt
		}

		if eventType != "" {
			events = append(events, map[string]interface{}{
				"event_type":    eventType,
				"ip_address":    ip,
				"mac_address":   mac,
				"host_name":     host,
				"vendor":        vendor,
				"lease_type":    ltype,
				"lease_expires": expires,
			})
		}

		d.leaseCache[ip] = cachedLease{
			MAC:          mac,
			HostName:     host,
			Vendor:       vendor,
			LeaseType:    ltype,
			LeaseExpires: expires,
			IssuedAt:     issuedAt,
		}

		leaseList = append(leaseList, map[string]interface{}{
			"ip_address":    ip,
			"mac_address":   mac,
			"host_name":     host,
			"vendor":        vendor,
			"lease_expires": expires,
			"type":          ltype,
			"issued_at":     issuedAt.Format(time.RFC3339),
		})
	}

	// Detect releases (leases no longer in response)
	for ip, prev := range d.leaseCache {
		if !seenIPs[ip] {
			events = append(events, map[string]interface{}{
				"event_type":    "release",
				"ip_address":    ip,
				"mac_address":   prev.MAC,
				"host_name":     prev.HostName,
				"vendor":        prev.Vendor,
				"lease_type":    prev.LeaseType,
				"lease_expires": prev.LeaseExpires,
			})
			delete(d.leaseCache, ip)
		}
	}
	d.cacheMu.Unlock()

	if len(events) == 0 {
		return
	}

	// Push only the events + fresh leases, not the heavy metrics
	payload := map[string]interface{}{
		"host":        d.cfg.Host,
		"name":        d.cfg.Name,
		"dhcp_leases": leaseList,
		"dhcp_events": events,
		"fast_poll":   true,
	}
	if err := p.Client.IngestSonicwall(payload); err != nil {
		slog.Warn("fast poll ingest failed", "host", d.cfg.Host, "err", err)
	} else {
		slog.Info("fast poll", "host", d.cfg.Host, "events", len(events), "leases", len(leaseList))
	}
}

func (p *Poller) pollDevice(d *deviceState) {
	logger := slog.With("sonicwall", d.cfg.Name, "host", d.cfg.Host)

	if !d.ensureSession() {
		logger.Error("cannot establish session")
		return
	}
	// Session blijft open — fastLoop en keepAliveLoop gebruiken hem ook

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

	// DHCP leases worden door fastLoop gedaan, hier niet

	// DHCP scopes (elke 5 min genoeg — slow poll)
	dhcpScopes := []map[string]interface{}{}
	if res := d.get("/dhcp-server/ipv4/scopes/dynamic"); res != nil {
		for _, s := range extractScopes(res, "dynamic") {
			dhcpScopes = append(dhcpScopes, s)
		}
	}
	if res := d.get("/dhcp-server/ipv4/scopes/static"); res != nil {
		for _, s := range extractScopes(res, "static") {
			dhcpScopes = append(dhcpScopes, s)
		}
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
		"dhcp_scopes": dhcpScopes,
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

// extractScopes parses /dhcp-server/ipv4/scopes/{dynamic,static} response
func extractScopes(res map[string]interface{}, scopeType string) []map[string]interface{} {
	out := []map[string]interface{}{}
	// Path: dhcp_server.ipv4.scope.{dynamic|static} = array
	server, _ := res["dhcp_server"].(map[string]interface{})
	if server == nil {
		return out
	}
	ipv4, _ := server["ipv4"].(map[string]interface{})
	if ipv4 == nil {
		return out
	}
	scope, _ := ipv4["scope"].(map[string]interface{})
	if scope == nil {
		return out
	}
	arr, _ := scope[scopeType].([]interface{})
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, map[string]interface{}{
			"scope_from":      getString(m, "from"),
			"scope_to":        getString(m, "to"),
			"netmask":         getString(m, "netmask"),
			"default_gateway": getString(m, "default_gateway"),
			"domain_name":     getString(m, "domain_name"),
			"lease_time":      m["lease_time"],
			"scope_type":      scopeType,
			"label":           getString(m, "comment"),
			"enabled":         getBool(m, "enable"),
		})
	}
	return out
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
