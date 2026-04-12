package switches

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

var macRegex = regexp.MustCompile(`^([0-9a-fA-F]{2}[:.-]){5}[0-9a-fA-F]{2}$`)

// ParseMACTable parses the output of `show mac address-table` on CBS350.
//
// Example:
//
//	Vlan   Mac Address        Port       Type
//	-----  -----------------  ---------  --------
//	1      00:11:22:33:44:55  gi1/0/1    dynamic
//	10     aa:bb:cc:dd:ee:ff  gi1/0/5    dynamic
//	1      00:00:00:00:00:01  CPU        management
func ParseMACTable(out string) []api.MACEntry {
	var results []api.MACEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "vlan") || strings.HasPrefix(trimmed, "---") {
			continue
		}
		if strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">") {
			continue
		}
		if strings.Contains(trimmed, "More:") || strings.Contains(trimmed, "Quit:") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}

		// MAC moet in fields[1] staan
		if !macRegex.MatchString(fields[1]) {
			continue
		}

		vlan, _ := strconv.Atoi(fields[0])
		macType := ""
		if len(fields) >= 4 {
			macType = strings.ToLower(fields[3])
		}

		results = append(results, api.MACEntry{
			VLAN:       vlan,
			MACAddress: strings.ToLower(fields[1]),
			Port:       fields[2],
			Type:       macType,
		})
	}
	return results
}
