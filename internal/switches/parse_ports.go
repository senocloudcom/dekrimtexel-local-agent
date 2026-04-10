package switches

import (
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ParsePortStatus parses the output of `show interfaces status` from a CBS350.
//
// Expected format (columns can wiggle):
//
//	Port     Type         Duplex  Speed Neg      ctrl State       Pressure Mode
//	-------- ------------ ------  ----- -------- ---- ----------- -------- -------
//	gi1/0/1  1G-Copper    Full    100   Enabled  Off  Up          Disabled On
//	gi1/0/2  1G-Copper    --      --    --       --   Down        --       --
//	Po1      -- ... (port channels, skip)
//
// The "State" column is at index 6 (0-based).
func ParsePortStatus(out string) []api.PortState {
	var results []api.PortState
	lines := strings.Split(out, "\n")

	dataStarted := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip headers and dashes
		if strings.HasPrefix(trimmed, "Port") || strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "===") {
			dataStarted = true
			continue
		}
		if !dataStarted {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 7 {
			continue
		}

		port := fields[0]
		// Skip port-channels (Po1, Po2, ...)
		if strings.HasPrefix(strings.ToLower(port), "po") {
			continue
		}

		speed := fields[3]
		state := fields[6]

		status := strings.ToLower(state)
		if status != "up" && status != "down" {
			// "Not Present" or similar: map to "down"
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
