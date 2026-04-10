package switches

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// portPrefix matches CBS350 port names: te1/0/22, gi1/0/1, fa0/1, etc.
var portPrefix = regexp.MustCompile(`^(te|gi|fa|xg|tw|fo|hu)\d`)

// ParseLLDPNeighbors parses the output of `show lldp neighbors` from a CBS350.
//
// Example output:
//
//	Port        Device ID          Port ID         System Name    Capabilities  TTL
//	--------- ----------------- ----------------- ----------------- ------------ -----
//	te1/0/1   a0:f8:49:f2:4c:d4     te1/0/22         KGS-FIBER01        B, R      93
//	gi1/0/5   00:11:22:33:44:55     Gi0/1            other-switch       B          120
//
// We don't rely on the header — we just match data rows by checking that the
// first column starts with a port prefix (te/gi/fa/etc).
func ParseLLDPNeighbors(out string) []api.TopologyEntry {
	var results []api.TopologyEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip header rows, separators, and shell prompts
		if strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "===") {
			continue
		}
		if strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">") {
			continue
		}
		// Skip "More:" / "Quit:" paging artifacts
		if strings.Contains(trimmed, "More:") || strings.Contains(trimmed, "Quit:") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}

		// First field must look like a port (te1/0/x, gi1/0/x, ...)
		if !portPrefix.MatchString(strings.ToLower(fields[0])) {
			continue
		}

		localPort := fields[0]
		deviceID := fields[1]
		remotePort := fields[2]
		systemName := fields[3]

		// Capabilities can span multiple fields ("B, R") until we hit the TTL number
		var caps []string
		for _, p := range fields[4:] {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
				break // TTL field
			}
			caps = append(caps, strings.Trim(p, ","))
		}
		capabilities := strings.Join(caps, ", ")

		results = append(results, api.TopologyEntry{
			LocalPort:    localPort,
			DeviceID:     deviceID,
			RemotePort:   remotePort,
			RemoteName:   systemName,
			Capabilities: capabilities,
		})
	}
	return results
}
