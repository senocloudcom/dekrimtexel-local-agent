package switches

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ParseSTPDetail parses `show spanning-tree detail` output for CBS350/CBS220
// switches into per-port STP state. Port-of the Python parser in
// dekrimtexel-agent/python-switch-agent/tools/stp.py.
func ParseSTPDetail(output string) []api.STPPortState {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	// Split into per-port blocks. A block starts with "Port gi1/0/X enabled/disabled".
	// We prepend a newline so the first block is also caught by the lookahead split.
	reSplit := regexp.MustCompile(`(?im)\nPort\s+(?:gi|te|fa)\d+/\d+/\d+\s+`)
	// Go's regexp has no lookahead, so we split on the pattern and then re-attach
	// each header by using FindAllStringIndex.
	indices := reSplit.FindAllStringIndex("\n"+output, -1)
	if len(indices) == 0 {
		return nil
	}

	padded := "\n" + output
	var blocks []string
	for i, idx := range indices {
		start := idx[0]
		var end int
		if i+1 < len(indices) {
			end = indices[i+1][0]
		} else {
			end = len(padded)
		}
		blocks = append(blocks, padded[start:end])
	}

	rePortHeader := regexp.MustCompile(`(?i)Port\s+((?:gi|te|fa)\d+/\d+/\d+)\s+(enabled|disabled)`)
	reStateRole := regexp.MustCompile(`(?is)State:\s*(\S+).*?Role:\s*(\S+)`)
	rePortCost := regexp.MustCompile(`Port cost:\s*(\d+)`)
	reType := regexp.MustCompile(`Type:\s*\S+\s*\(configured:\S+\s*\)\s*(\S+)`)
	rePortFast := regexp.MustCompile(`(?i)Port Fast:\s*(Yes|No)\s*\(configured:\s*(\S+?)\s*\)`)
	reBPDUGuard := regexp.MustCompile(`(?i)BPDU guard:\s*(Enabled|Disabled)`)
	reRootGuard := regexp.MustCompile(`(?i)Guard root:\s*(Enabled|Disabled)`)
	reTransitions := regexp.MustCompile(`transitions to forwarding state:\s*(\d+)`)
	reBPDU := regexp.MustCompile(`BPDU:\s*sent\s+(\d+),\s*received\s+(\d+)`)

	var ports []api.STPPortState
	for _, block := range blocks {
		header := rePortHeader.FindStringSubmatch(block)
		if header == nil {
			continue
		}
		p := api.STPPortState{
			Port:    strings.ToLower(header[1]),
			Enabled: strings.EqualFold(header[2], "enabled"),
		}

		if m := reStateRole.FindStringSubmatch(block); m != nil {
			p.State = strings.ToLower(m[1])
			p.Role = strings.ToLower(m[2])
		}
		if m := rePortCost.FindStringSubmatch(block); m != nil {
			if v, err := strconv.Atoi(m[1]); err == nil {
				p.PortCost = v
			}
		}
		if m := reType.FindStringSubmatch(block); m != nil {
			p.Protocol = strings.ToUpper(m[1])
		}
		if m := rePortFast.FindStringSubmatch(block); m != nil {
			p.EdgePort = strings.EqualFold(m[1], "yes")
			p.EdgePortConfigured = strings.Title(strings.ToLower(m[2])) //nolint:staticcheck
		}
		if m := reBPDUGuard.FindStringSubmatch(block); m != nil {
			p.BPDUGuard = strings.EqualFold(m[1], "enabled")
		}
		if m := reRootGuard.FindStringSubmatch(block); m != nil {
			p.RootGuard = strings.EqualFold(m[1], "enabled")
		}
		if m := reTransitions.FindStringSubmatch(block); m != nil {
			if v, err := strconv.Atoi(m[1]); err == nil {
				p.Transitions = v
			}
		}
		if m := reBPDU.FindStringSubmatch(block); m != nil {
			if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				p.BPDUSent = v
			}
			if v, err := strconv.ParseInt(m[2], 10, 64); err == nil {
				p.BPDUReceived = v
			}
		}

		ports = append(ports, p)
	}

	return ports
}

// ParseSTPGlobal extracts the per-switch STP summary (mode + root bridge +
// topology change counters) from the header of `show spanning-tree detail`.
func ParseSTPGlobal(output string) *api.STPGlobal {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	// Header = everything before the first per-port block
	header := output
	if idx := strings.Index(output, "Port "); idx >= 0 {
		header = output[:idx]
	}

	g := &api.STPGlobal{}

	if m := regexp.MustCompile(`(?i)mode\s*:?\s*(STP|RSTP|MSTP|rapid-pvst)`).FindStringSubmatch(header); m != nil {
		mode := strings.ToUpper(m[1])
		if mode == "RAPID-PVST" {
			mode = "RSTP"
		}
		g.Mode = mode
	}
	if m := regexp.MustCompile(`(?is)Root\s+ID.*?Priority\s*:?\s*(\d+)`).FindStringSubmatch(header); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil {
			g.RootBridgePriority = &v
		}
	}
	if m := regexp.MustCompile(`(?is)Root\s+ID.*?Address\s*:?\s*([\da-fA-F:.\-]+)`).FindStringSubmatch(header); m != nil {
		g.RootBridgeAddress = m[1]
	}
	if m := regexp.MustCompile(`(?i)topology changes\s*:?\s*(\d+)`).FindStringSubmatch(header); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil {
			g.TopologyChanges = &v
		}
	}
	if m := regexp.MustCompile(`(?i)Last topology change.*?:\s*(.+)`).FindStringSubmatch(header); m != nil {
		g.LastTopologyChange = strings.TrimSpace(m[1])
	}

	// Return nil if nothing useful was parsed
	if g.Mode == "" && g.RootBridgePriority == nil && g.RootBridgeAddress == "" &&
		g.TopologyChanges == nil && g.LastTopologyChange == "" {
		return nil
	}
	return g
}
