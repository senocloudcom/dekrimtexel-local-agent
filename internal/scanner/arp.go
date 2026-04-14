package scanner

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// ArpTable leest de systeem ARP tabel en retourneert een ip → mac mapping.
// Op Windows is het formaat "10.0.0.1   aa-bb-cc-dd-ee-ff   dynamic",
// Unix "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0".
//
// We normaliseren MAC naar lowercase met :-separators.
func ArpTable(ctx context.Context) map[string]string {
	out := make(map[string]string)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "arp", "-a")
	} else {
		cmd = exec.CommandContext(ctx, "arp", "-an")
	}
	data, err := cmd.Output()
	if err != nil {
		return out
	}

	reWin := regexp.MustCompile(`^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17})`)
	reUnix := regexp.MustCompile(`\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+([0-9a-fA-F:]{11,17})`)

	for _, line := range strings.Split(string(data), "\n") {
		if m := reWin.FindStringSubmatch(line); m != nil {
			mac := strings.ToLower(strings.ReplaceAll(m[2], "-", ":"))
			out[m[1]] = mac
			continue
		}
		if m := reUnix.FindStringSubmatch(line); m != nil {
			mac := normalizeMAC(m[2])
			if mac != "" {
				out[m[1]] = mac
			}
		}
	}
	return out
}

func normalizeMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return ""
	}
	var out []string
	for _, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		out = append(out, strings.ToLower(p))
	}
	return strings.Join(out, ":")
}
