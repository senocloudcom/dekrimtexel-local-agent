package switches

import (
	"strconv"
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ParseInterfaceCounters parses the output of `show interfaces counters` on CBS350.
//
// Example (simplified):
//
//	Port       InOctets    InUcastPkts  InMcastPkts  InBcastPkts
//	gi1/0/1    1234567     1000         50           10
//	...
//
// CBS350 shows a lot of columns; we extract common ones.
// The command `show interfaces counters errors` gives error specifics.
func ParseInterfaceCounters(out string) []api.InterfaceStat {
	results := make(map[string]*api.InterfaceStat)

	lines := strings.Split(out, "\n")
	var headers []string

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		lower := strings.ToLower(trimmed)
		// Detect header line
		if strings.HasPrefix(lower, "port") && (strings.Contains(lower, "octets") || strings.Contains(lower, "errors") || strings.Contains(lower, "pkts")) {
			headers = strings.Fields(lower)
			continue
		}

		if strings.HasPrefix(trimmed, "---") {
			continue
		}
		if strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">") {
			continue
		}
		if strings.Contains(trimmed, "More:") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}

		port := fields[0]
		lcPort := strings.ToLower(port)
		if !portPrefix.MatchString(lcPort) {
			continue
		}

		stat, ok := results[port]
		if !ok {
			stat = &api.InterfaceStat{Port: port}
			results[port] = stat
		}

		// Map headers to fields
		for i, h := range headers {
			if i >= len(fields) {
				break
			}
			val, err := strconv.ParseInt(fields[i], 10, 64)
			if err != nil {
				continue
			}
			switch {
			case strings.Contains(h, "inoctet"):
				stat.InOctets = val
			case strings.Contains(h, "outoctet"):
				stat.OutOctets = val
			case h == "inerrors" || h == "in-err" || h == "rxerrors":
				stat.InErrors = val
			case h == "outerrors" || h == "out-err" || h == "txerrors":
				stat.OutErrors = val
			case strings.Contains(h, "crc") || strings.Contains(h, "fcs"):
				stat.CRCErrors = val
			case strings.Contains(h, "collision"):
				stat.Collisions = val
			case h == "indiscards" || h == "in-disc":
				stat.InDiscards = val
			case h == "outdiscards" || h == "out-disc":
				stat.OutDiscards = val
			}
		}
	}

	var out2 []api.InterfaceStat
	for _, v := range results {
		out2 = append(out2, *v)
	}
	return out2
}
