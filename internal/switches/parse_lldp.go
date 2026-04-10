package switches

import (
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ParseLLDPNeighbors parses the output of `show lldp neighbors` from a CBS350.
//
// Typical output:
//
//	Port       Device ID        Port ID       System Name   Capabilities TTL
//	---------- ---------------- ------------- ------------- ------------ ----
//	gi1/0/1    0011.2233.4455   Gi1/0/1       core-switch-1 B            120
//
// We extract: LocalPort, RemoteName (System Name), RemotePort (Port ID),
// Capabilities, DeviceID.
func ParseLLDPNeighbors(out string) []api.TopologyEntry {
	var results []api.TopologyEntry
	lines := strings.Split(out, "\n")

	dataStarted := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Port") && strings.Contains(trimmed, "Device ID") {
			dataStarted = true
			continue
		}
		if strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "===") {
			continue
		}
		if !dataStarted {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 5 {
			continue
		}

		results = append(results, api.TopologyEntry{
			LocalPort:    fields[0],
			DeviceID:     fields[1],
			RemotePort:   fields[2],
			RemoteName:   fields[3],
			Capabilities: fields[4],
		})
	}
	return results
}
