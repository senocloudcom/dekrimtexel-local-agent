package switches

import (
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ParsePortStatus parses the output of `show interfaces status` from a CBS350.
//
// Example:
//
//	Port     Type         Duplex  Speed Neg      ctrl State       Pressure Mode
//	-------- ------------ ------  ----- -------- ---- ----------- -------- -------
//	gi1/0/1  1G-Copper    Full    100   Enabled  Off  Up          Disabled On
//	te1/0/1  10G-Fiber    --      --    --       --   Down        --       --
//	Po1      ...                                                            (port channels — skip)
//
// Like the LLDP parser, we don't rely on header detection — we match data rows
// by checking that the first column looks like a port name. The "State" column
// is at index 6 (0-based) on standard CBS350 output.
func ParsePortStatus(out string) []api.PortState {
	var results []api.PortState
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip headers, dashes, and prompts
		if strings.HasPrefix(trimmed, "Port") || strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "===") {
			continue
		}
		if strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">") {
			continue
		}
		if strings.Contains(trimmed, "More:") || strings.Contains(trimmed, "Quit:") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 7 {
			continue
		}

		port := fields[0]
		// Only accept lines starting with a port-like name
		lc := strings.ToLower(port)
		if !portPrefix.MatchString(lc) {
			// Skip port-channels (Po1, Po2, ...)
			continue
		}

		speed := fields[3]
		state := fields[6]

		status := strings.ToLower(state)
		if status != "up" && status != "down" {
			status = "down"
		}

		results = append(results, api.PortState{
			Port:   port,
			Status: status,
			Speed:  speed,
		})
	}
	return results
}
