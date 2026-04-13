package switches

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ParseVLANTable parses `show vlan` output for CBS350 (simple layout) and
// CBS220/C1300 (Tagged Ports + Untagged Ports + Created by columns). The
// CBS220 format is detected from the header line and parsed column-based
// using the `----` separator widths; otherwise a whitespace-based split
// is used.
func ParseVLANTable(output string) []api.VLAN {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")

	// Detect CBS220 layout: header mentions both "Tagged Ports" and
	// "UnTagged Ports" (spelling varies), with a `----` separator that
	// defines column widths.
	headerIdx, sepIdx := -1, -1
	for i, line := range lines {
		lower := strings.ToLower(line)
		if headerIdx < 0 && strings.Contains(lower, "vlan") &&
			strings.Contains(lower, "tagged") && strings.Contains(lower, "untagged") {
			headerIdx = i
		}
		if headerIdx >= 0 && i > headerIdx && regexp.MustCompile(`^\s*-{3,}`).MatchString(line) {
			sepIdx = i
			break
		}
	}
	if headerIdx >= 0 && sepIdx > headerIdx {
		return parseVLANTableCBS220(lines, sepIdx)
	}

	// Fallback: CBS350-style whitespace parsing.
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
			cur.Ports = append(cur.Ports, extractPorts(strings.TrimSpace(line))...)
		}
	}
	if cur != nil {
		vlans = append(vlans, *cur)
	}
	return vlans
}

// parseVLANTableCBS220 parses VLAN output using column positions determined
// from the `----` separator line (lines[sepIdx]). Columns are:
//
//	Vlan | Name | Tagged Ports | UnTagged Ports | Created by
func parseVLANTableCBS220(lines []string, sepIdx int) []api.VLAN {
	sep := lines[sepIdx]
	// Find column spans: groups of '-' separated by whitespace
	var spans [][2]int // [start, end) per column
	i := 0
	for i < len(sep) {
		if sep[i] == '-' {
			start := i
			for i < len(sep) && sep[i] == '-' {
				i++
			}
			spans = append(spans, [2]int{start, i})
			continue
		}
		i++
	}
	if len(spans) < 4 {
		// Unexpected layout — bail to empty rather than garbage
		return nil
	}

	slice := func(line string, col [2]int) string {
		if col[0] >= len(line) {
			return ""
		}
		end := col[1]
		if end > len(line) {
			end = len(line)
		}
		return strings.TrimSpace(line[col[0]:end])
	}

	var vlans []api.VLAN
	for _, line := range lines[sepIdx+1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		vlanStr := slice(line, spans[0])
		id, err := strconv.Atoi(vlanStr)
		if err != nil {
			continue
		}
		name := slice(line, spans[1])
		tagged := slice(line, spans[2])
		untagged := slice(line, spans[3])

		var ports []string
		ports = append(ports, extractPorts(tagged)...)
		ports = append(ports, extractPorts(untagged)...)

		vlans = append(vlans, api.VLAN{
			VLANID: id,
			Name:   name,
			Ports:  ports,
		})
	}
	return vlans
}

var (
	reLongRange   = regexp.MustCompile(`(?i)^(gi|te|fa)((\d+/\d+/)(\d+))-(?:gi|te|fa)\d+/\d+/(\d+)$`)
	reShortRange  = regexp.MustCompile(`(?i)^(gi|te|fa)((\d+/\d+/)(\d+))-(\d+)$`)
	reCBS220Range = regexp.MustCompile(`(?i)^(gi|te|fa)(\d+)-(\d+)$`) // gi9-10 style (CBS220, no stack/slot)
	rePoRange     = regexp.MustCompile(`(?i)^(Po)(\d+)-(\d+)$`)
	rePortName    = regexp.MustCompile(`(?i)^(gi|te|fa|po)\d`)
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
		if m := reCBS220Range.FindStringSubmatch(part); m != nil {
			start, _ := strconv.Atoi(m[2])
			end, _ := strconv.Atoi(m[3])
			prefix := strings.ToLower(m[1])
			for i := start; i <= end; i++ {
				ports = append(ports, fmt.Sprintf("%s%d", prefix, i))
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
// CBS220 uses "Name: gi1" as per-port block marker while CBS350 uses
// "Information of gi1/0/1". SSH paging artifacts (ANSI escape codes,
// "More:" prompts) are stripped before splitting.
func ParseSwitchport(output string) []api.VLANPortAssignment {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	// Strip ANSI escape sequences and SSH pager artifacts that otherwise
	// split blocks in weird places.
	reANSI := regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	output = reANSI.ReplaceAllString(output, "")
	output = regexp.MustCompile(`More:\s*<space>[^\r\n]*`).ReplaceAllString(output, "")

	// Find per-port block boundaries. A block starts at a "Name: <port>"
	// (CBS220), "Information of <port>" (CBS350) or "Port: <port>".
	reBlockStart := regexp.MustCompile(`(?mi)^\s*(?:Name|Information\s+of|Port)\s*:?\s*((?:gi|te|fa|po)\d\S*)`)
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

	rePortName2 := regexp.MustCompile(`(?i)(?:Name|Information\s+of|Port)\s*:?\s*((?:gi|te|fa|po)\d\S*)`)
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
