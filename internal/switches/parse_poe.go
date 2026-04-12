package switches

import (
	"strconv"
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ParsePoEStatus parses the output of `show power inline` on CBS350.
//
// Example:
//
//	Port     Powered Device  Power(W)  Class  Status    Priority
//	-------- --------------- --------- ------ --------- --------
//	gi1/0/1  IP Phone        6.5       Class2 on        high
//	gi1/0/2                  0.0       --     off       low
//	gi1/0/3  Access Point    12.8      Class3 on        crit
func ParsePoEStatus(out string) []api.PoEPortStatus {
	var results []api.PoEPortStatus
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Port") || strings.HasPrefix(trimmed, "---") {
			continue
		}
		if strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">") {
			continue
		}
		if strings.Contains(trimmed, "More:") || strings.Contains(trimmed, "Quit:") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}

		port := fields[0]
		lc := strings.ToLower(port)
		if !portPrefix.MatchString(lc) {
			continue
		}

		// Parse from end backwards: priority, status, class, power, device (optional)
		// Last field = priority, second-to-last = status, third-to-last = class, fourth-to-last = power
		if len(fields) < 5 {
			continue
		}
		priority := fields[len(fields)-1]
		status := strings.ToLower(fields[len(fields)-2])
		class := fields[len(fields)-3]
		powerStr := fields[len(fields)-4]

		power, _ := strconv.ParseFloat(powerStr, 64)

		// Device name is everything between port and power
		device := ""
		if len(fields) > 5 {
			device = strings.Join(fields[1:len(fields)-4], " ")
		}

		enabled := status == "on" || status == "searching"

		results = append(results, api.PoEPortStatus{
			Port:       port,
			Enabled:    enabled,
			Status:     status,
			PowerWatts: power,
			Class:      class,
			Priority:   priority,
			DeviceType: device,
		})
	}
	return results
}
