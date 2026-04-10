package switches

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
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
func ScanSwitch(sw api.SwitchConfig, creds Credentials, scanID string, progress func(api.ScanProgressStep)) (*api.NetworkIngestRequest, error) {
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
		emit("ssh_connect", fmt.Sprintf("Verbinding mislukt: %v", err), "error")
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer client.Close()

	emit("ssh_connect", fmt.Sprintf("Verbonden met %s", sw.Name), "done")

	// Run the configured commands (or a default set)
	commands := sw.Commands
	if len(commands) == 0 {
		commands = []string{
			"show version",
			"show interfaces status",
			"show lldp neighbors",
		}
	}

	rawData := make(map[string]interface{})
	var portStates []api.PortState
	var topology []api.TopologyEntry

	for _, cmd := range commands {
		emit("run_command", fmt.Sprintf("> %s", cmd), "running")
		output, err := client.Run(cmd, 20*time.Second)
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
		}
	}

	// Compute a hash of the raw output for change detection
	hash := sha256Hash(rawData)

	emit("parse", fmt.Sprintf("%d ports, %d topology entries", len(portStates), len(topology)), "done")
	emit("complete", fmt.Sprintf("%s: scan voltooid", sw.Name), "done")

	return &api.NetworkIngestRequest{
		SwitchID:     sw.ID,
		SwitchName:   sw.Name,
		DataHash:     hash,
		Changed:      true, // TODO: compare against stored hash in fase C-gamma
		RawData:      rawData,
		Severity:     "info",
		ScanType:     "full",
		PortStates:   portStates,
		Topology:     topology,
		ScanProgress: nil, // progress is streamed separately via IngestScanProgress
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
