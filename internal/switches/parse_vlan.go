package switches

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ParseVLANTable parses `show vlan` output (CBS350/CBS220) into a list of
// VLANs with their member ports. Supports the compact range notation
// (gi1/0/1-24, te1/0/1-4, Po1-8) that CBS/Sx-series use.
func ParseVLANTable(output string) []api.VLAN {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")

	// Find the first line of data by scanning for the header separator (---)
	// or a "VLAN   Name" header.
	reSep := regexp.MustCompile(`^\s*-{3,}`)
	reHeader := regexp.MustCompile(`(?i)^\s*VLAN\s+Name\s+`)
	dataStart := 0
	for i, line := range lines {
		if reSep.MatchString(line) {
			dataStart = i + 1
			break
		}
		if reHeader.MatchString(line) {
			dataStart = i + 1
		}
	}

	reVLAN := regexp.MustCompile(`^\s*(\d+)\s+(\S+)\s+(.*)`)

	var vlans []api.VLAN
	var cur *api.VLAN
	for _, line := range lines[dataStart:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m := reVLAN.FindStringSubmatch(line); m != nil {
			if cur != nil {
				vlans = append(vlans, *cur)
			}
			id, _ := strconv.Atoi(m[1])
			cur = &api.VLAN{
				VLANID: id,
				Name:   m[2],
				Ports:  extractPorts(strings.TrimSpace(m[3])),
			}
		} else if cur != nil {
			// continuation line — extra ports for the previous VLAN
			cur.Ports = append(cur.Ports, extractPorts(strings.TrimSpace(line))...)
		}
	}
	if cur != nil {
		vlans = append(vlans, *cur)
	}
	return vlans
}

var (
	reLongRange  = regexp.MustCompile(`(?i)^(gi|te|fa)((\d+/\d+/)(\d+))-(?:gi|te|fa)\d+/\d+/(\d+)$`)
	reShortRange = regexp.MustCompile(`(?i)^(gi|te|fa)((\d+/\d+/)(\d+))-(\d+)$`)
	rePoRange    = regexp.MustCompile(`(?i)^(Po)(\d+)-(\d+)$`)
	rePortName   = regexp.MustCompile(`(?i)^(gi|te|fa|po)\d`)
)

func extractPorts(text string) []string {
	if text == "" {
		return nil
	}
	var ports []string
	for _, raw := range strings.Split(text, ",") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		if m := reLongRange.FindStringSubmatch(part); m != nil {
			start, _ := strconv.Atoi(m[4])
			end, _ := strconv.Atoi(m[5])
			prefix := strings.ToLower(m[1])
			slot := m[3]
			for i := start; i <= end; i++ {
				ports = append(ports, fmt.Sprintf("%s%s%d", prefix, slot, i))
			}
			continue
		}
		if m := reShortRange.FindStringSubmatch(part); m != nil {
			start, _ := strconv.Atoi(m[4])
			end, _ := strconv.Atoi(m[5])
			prefix := strings.ToLower(m[1])
			slot := m[3]
			for i := start; i <= end; i++ {
				ports = append(ports, fmt.Sprintf("%s%s%d", prefix, slot, i))
			}
			continue
		}
		if m := rePoRange.FindStringSubmatch(part); m != nil {
			start, _ := strconv.Atoi(m[2])
			end, _ := strconv.Atoi(m[3])
			for i := start; i <= end; i++ {
				ports = append(ports, fmt.Sprintf("po%d", i))
			}
			continue
		}
		if rePortName.MatchString(part) {
			ports = append(ports, strings.ToLower(part))
		}
	}
	return ports
}

// ParseSwitchport parses `show interfaces switchport` for CBS350/CBS220.
// Supports the "Information of <port>" block format (CBS350) as primary
// strategy, falling back to a simpler block split if that yields nothing.
func ParseSwitchport(output string) []api.VLANPortAssignment {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	// Split on "Information of <port>" or a bare port header at line-start.
	reBlockStart := regexp.MustCompile(`(?mi)^(?:Information\s+of\s+)?((?:gi|te|fa|po)\d\S*)\s*:?\s*$|(?i)Port\s*:\s*((?:gi|te|fa|po)\d\S*)`)
	matches := reBlockStart.FindAllStringIndex(output, -1)
	if len(matches) == 0 {
		return nil
	}

	var blocks []string
	for i, idx := range matches {
		var end int
		if i+1 < len(matches) {
			end = matches[i+1][0]
		} else {
			end = len(output)
		}
		blocks = append(blocks, output[idx[0]:end])
	}

	rePortName2 := regexp.MustCompile(`(?i)((?:gi|te|fa|po)\d\S*)`)
	reMode1 := regexp.MustCompile(`(?i)(?:VLAN\s+Membership\s+Mode|Port\s+Mode|Administrative\s+Mode|Operational\s+Mode)\s*:\s*(\S+)`)
	reMode2 := regexp.MustCompile(`(?i)Mode\s*:\s*(Access|Trunk|General|Hybrid)`)
	reAccess := regexp.MustCompile(`(?i)Access\s+(?:Mode\s+)?VLAN\s*:\s*(\d+)`)
	reNative1 := regexp.MustCompile(`(?i)(?:Trunk(?:ing)?)\s+Native\s+(?:Mode\s+)?VLAN\s*:\s*(\d+)`)
	reNative2 := regexp.MustCompile(`(?i)Native\s+(?:Mode\s+)?VLAN\s*:\s*(\d+)`)
	reNative3 := regexp.MustCompile(`(?i)Ingress\s+UnTagged\s+VLAN\s*\([^)]*\)\s*:\s*(\d+)`)
	reTrunk := regexp.MustCompile(`(?i)(?:Trunking\s+VLANs?\s+(?:Enabled|Allowed)|Allowed\s+VLANs?)\s*:\s*(.+)`)

	var result []api.VLANPortAssignment
	for _, block := range blocks {
		pm := rePortName2.FindStringSubmatch(block)
		if pm == nil {
			continue
		}
		port := strings.ToLower(pm[1])

		a := api.VLANPortAssignment{Port: port}

		if m := reMode1.FindStringSubmatch(block); m != nil {
			mode := strings.ToLower(m[1])
			if mode == "hybrid" {
				mode = "general"
			}
			a.Mode = mode
		} else if m := reMode2.FindStringSubmatch(block); m != nil {
			mode := strings.ToLower(m[1])
			if mode == "hybrid" {
				mode = "general"
			}
			a.Mode = mode
		}

		if m := reAccess.FindStringSubmatch(block); m != nil {
			if v, err := strconv.Atoi(m[1]); err == nil {
				a.AccessVLAN = &v
			}
		}
		for _, re := range []*regexp.Regexp{reNative1, reNative2, reNative3} {
			if m := re.FindStringSubmatch(block); m != nil {
				if v, err := strconv.Atoi(m[1]); err == nil {
					a.NativeVLAN = &v
					break
				}
			}
		}
		if m := reTrunk.FindStringSubmatch(block); m != nil {
			a.TrunkVLANs = strings.TrimSpace(m[1])
		}

		// Only keep entries with at least a mode or access vlan, otherwise
		// we're emitting noise for every random line that starts with a port
		// token.
		if a.Mode == "" && a.AccessVLAN == nil {
			continue
		}
		result = append(result, a)
	}
	return result
}
