package switches

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
	"github.com/senocloudcom/dekrimtexel-local-agent/internal/crypto"
)

// Credentials holds decrypted SSH credentials for a single scan.
// Exists only in memory during a scan, never persisted.
type Credentials struct {
	Username string
	Password string
}

// DecryptCredentials takes encrypted credentials from /v1/agent/config and
// returns decrypted plaintext using the shared AES-256-GCM master key.
func DecryptCredentials(keyHex string, enc api.SSHCredentialsEncrypted) (Credentials, error) {
	username, err := crypto.Decrypt(keyHex, enc.Username)
	if err != nil {
		return Credentials{}, fmt.Errorf("decrypt username: %w", err)
	}
	password, err := crypto.Decrypt(keyHex, enc.Password)
	if err != nil {
		return Credentials{}, fmt.Errorf("decrypt password: %w", err)
	}
	return Credentials{Username: username, Password: password}, nil
}

// ScanSwitch runs the basic scan commands on a single switch and returns
// a populated NetworkIngestRequest ready to POST to /v1/ingest/network.
//
// Progress callbacks are made via the progress function, which should push
// a ScanProgressStep to the dashboard (e.g. via api.IngestScanProgress).
//
// This is fase C-beta: only ports + LLDP + raw output. STP/VLAN/MAC parsing
// comes in fase C-gamma.
// MACLookup resolves a MAC address to IP/hostname/vendor via external source (e.g. SonicWall DHCP)
type MACLookup func(mac string) (ip, hostname, vendor string)

func ScanSwitch(sw api.SwitchConfig, creds Credentials, scanID string, progress func(api.ScanProgressStep), macLookup MACLookup) (*api.NetworkIngestRequest, error) {
	logger := slog.With("switch", sw.Name, "host", sw.Host, "scan_id", scanID)
	logger.Info("scan start")

	emit := func(step, detail, status string) {
		if progress != nil {
			sid := sw.ID
			progress(api.ScanProgressStep{
				ScanID:   scanID,
				SwitchID: &sid,
				Step:     step,
				Detail:   detail,
				Status:   status,
			})
		}
	}

	emit("ssh_connect", fmt.Sprintf("Verbinden met %s (%s)...", sw.Name, sw.Host), "running")

	client, err := Connect(sw.Host, creds.Username, creds.Password, 15*time.Second)
	if err != nil {
		logger.Error("ssh connect failed", "err", err)
		// Categoriseer de error voor een duidelijker bericht in de modal
		errMsg := err.Error()
		var userMsg string
		switch {
		case strings.Contains(errMsg, "tcp dial") && strings.Contains(errMsg, "timeout"):
			userMsg = fmt.Sprintf("%s onbereikbaar (TCP timeout) — switch staat uit, niet in netwerk, of firewall blokkeert poort 22", sw.Host)
		case strings.Contains(errMsg, "tcp dial") && strings.Contains(errMsg, "refused"):
			userMsg = fmt.Sprintf("%s weigert verbinding (TCP refused) — SSH service is uit op switch", sw.Host)
		case strings.Contains(errMsg, "no route to host"):
			userMsg = fmt.Sprintf("%s — geen route naar host (VPN tunnel down of routing probleem)", sw.Host)
		case strings.Contains(errMsg, "ssh handshake") || strings.Contains(errMsg, "handshake refused"):
			userMsg = fmt.Sprintf("%s SSH handshake mislukt — switch ondersteunt waarschijnlijk de aangevraagde algorithms niet (oudere firmware?)", sw.Host)
		case strings.Contains(errMsg, "wait for user prompt") || strings.Contains(errMsg, "wait for password prompt"):
			userMsg = fmt.Sprintf("%s — switch reageert niet met login prompts (geen CBS350-compatible SSH?)", sw.Host)
		case strings.Contains(errMsg, "wait for # prompt") || strings.Contains(errMsg, "login may have failed"):
			userMsg = fmt.Sprintf("%s — login mislukt: SSH credentials klopen niet (check agent_ssh_username/password in dashboard)", sw.Host)
		case strings.Contains(errMsg, "unable to authenticate"):
			userMsg = fmt.Sprintf("%s — SSH authentication geweigerd door de switch", sw.Host)
		default:
			userMsg = fmt.Sprintf("Verbinding mislukt: %s", errMsg)
		}
		emit("ssh_connect", userMsg, "error")
		emit("complete", fmt.Sprintf("%s: SCAN MISLUKT", sw.Name), "error")
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer client.Close()

	emit("ssh_connect", fmt.Sprintf("Verbonden met %s", sw.Name), "done")

	// Run the configured commands (or a default set)
	commands := sw.Commands
	if len(commands) == 0 {
		commands = []string{
			"show version",
			"show interface status",
			"show lldp neighbors",
			"show mac address-table",
			"show power inline",
			"show interfaces counters",
			"show spanning-tree",
			"show spanning-tree detail",
			"show vlan",
			"show interfaces switchport",
		}
	}

	rawData := make(map[string]interface{})
	var portStates []api.PortState
	var topology []api.TopologyEntry
	var macTable []api.MACEntry
	var poeStatus []api.PoEPortStatus
	var interfaceStats []api.InterfaceStat

	for _, cmd := range commands {
		emit("run_command", fmt.Sprintf("> %s", cmd), "running")
		output, err := client.Run(cmd, 30*time.Second)
		if err != nil {
			logger.Warn("command failed", "cmd", cmd, "err", err)
			emit("run_command", fmt.Sprintf("Command '%s' faalde: %v", cmd, err), "error")
			// Continue with remaining commands
			continue
		}
		rawData[cmd] = output
		emit("run_command", fmt.Sprintf("%s — %d bytes", cmd, len(output)), "done")

		// Parse known commands
		switch cmd {
		case "show interfaces status", "show interface status":
			portStates = ParsePortStatus(output)
		case "show lldp neighbors":
			topology = ParseLLDPNeighbors(output)
		case "show mac address-table", "show mac-address-table":
			macTable = ParseMACTable(output)
		case "show power inline":
			poeStatus = ParsePoEStatus(output)
		case "show interfaces counters", "show interface counters":
			interfaceStats = ParseInterfaceCounters(output)
		}
	}

	// Compute a hash of the raw output for change detection
	hash := sha256Hash(rawData)

	// Build port_device_snapshots by correlating MAC table entries with DHCP lease cache
	portSnapshots := []api.PortDeviceSnapshot{}
	for _, m := range macTable {
		if m.Port == "" || m.MACAddress == "" {
			continue
		}
		// Skip CPU/management entries
		if strings.EqualFold(m.Port, "CPU") || strings.EqualFold(m.Type, "management") {
			continue
		}
		var ip, host, vendor string
		if macLookup != nil {
			ip, host, vendor = macLookup(m.MACAddress)
		}
		portSnapshots = append(portSnapshots, api.PortDeviceSnapshot{
			Port:       m.Port,
			MACAddress: strings.ToLower(m.MACAddress),
			IPAddress:  ip,
			Hostname:   host,
			Vendor:     vendor,
		})
	}

	emit("parse", fmt.Sprintf("%d ports, %d topology, %d MACs, %d PoE, %d stats, %d snapshots",
		len(portStates), len(topology), len(macTable), len(poeStatus), len(interfaceStats), len(portSnapshots)), "done")
	emit("complete", fmt.Sprintf("%s: scan voltooid", sw.Name), "done")

	return &api.NetworkIngestRequest{
		SwitchID:       sw.ID,
		SwitchName:     sw.Name,
		DataHash:       hash,
		Changed:        true,
		RawData:        rawData,
		Severity:       "info",
		ScanType:       "full",
		PortStates:     portStates,
		Topology:       topology,
		MACTable:       macTable,
		PoEStatus:      poeStatus,
		InterfaceStats: interfaceStats,
		PortSnapshots:  portSnapshots,
		ScanProgress:   nil,
	}, nil
}

// sha256Hash returns a deterministic hash of a map by concatenating
// sorted key/value pairs. For C-beta this is simple; in C-gamma we'll
// use a proper JSON canonical form.
func sha256Hash(data map[string]interface{}) string {
	// Simple approach: hash the string representation.
	// Not canonical but good enough for a first iteration.
	h := sha256.New()
	for k, v := range data {
		fmt.Fprintf(h, "%s=%v\n", k, v)
	}
	return hex.EncodeToString(h.Sum(nil))
}
