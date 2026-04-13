package switches

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/senocloudcom/dekrimtexel-local-agent/internal/api"
)

// ConfigureResult holds the outcome of a configure action on one switch.
type ConfigureResult struct {
	SwitchID   int
	SwitchName string
	Success    bool
	Output     string
	Error      string
}

// ConfigureSyslog connects to a switch and configures syslog forwarding.
// Supports both CBS350 (severity as keyword) and CBS220 (severity as number + facility).
// Detects model from `show version` output.
func ConfigureSyslog(host string, creds Credentials, model string, syslogHost string, syslogLevel string, timeout time.Duration) (string, error) {
	client, err := Connect(host, creds.Username, creds.Password, timeout)
	if err != nil {
		return "", fmt.Errorf("ssh connect: %w", err)
	}
	defer client.Close()

	// Detect CBS220 vs CBS350 — different CLI dialects
	modelLower := strings.ToLower(model)
	isCBS220 := strings.Contains(modelLower, "cbs220")

	// Normalize level — input kan keyword OF nummer zijn
	numToKeyword := map[string]string{
		"0": "emergencies", "1": "alerts", "2": "critical",
		"3": "errors", "4": "warnings", "5": "notifications",
		"6": "informational", "7": "debugging",
	}
	keywordToNum := map[string]string{
		"emergencies": "0", "alerts": "1", "critical": "2",
		"errors": "3", "warnings": "4", "notifications": "5",
		"informational": "6", "debugging": "7",
	}

	input := strings.ToLower(strings.TrimSpace(syslogLevel))
	var sevNum, sevKeyword string
	if k, ok := numToKeyword[input]; ok {
		// input was nummer
		sevNum = input
		sevKeyword = k
	} else if n, ok := keywordToNum[input]; ok {
		// input was keyword
		sevKeyword = input
		sevNum = n
	} else {
		// fallback
		sevKeyword = "warnings"
		sevNum = "4"
	}

	var loggingCmd string
	if isCBS220 {
		// CBS220: severity as number, include facility
		loggingCmd = fmt.Sprintf("logging host %s port 1514 severity %s facility local7", syslogHost, sevNum)
	} else {
		// CBS350: severity as keyword
		loggingCmd = fmt.Sprintf("logging host %s port 1514 severity %s", syslogHost, sevKeyword)
	}

	// Remove legacy logging host 172.16.0.1 (oude VPS setup) voordat we de
	// nieuwe zetten. Als die regel niet bestaat negeert de switch de 'no' regel.
	commands := []string{
		"configure",
		"no logging host 172.16.0.1",
		loggingCmd,
		"end",
		"write memory",
	}

	var output strings.Builder
	for _, cmd := range commands {
		out, err := client.Run(cmd, 10*time.Second)
		output.WriteString(fmt.Sprintf("> %s\n%s\n", cmd, out))
		// "no logging host" mag falen als die host niet bestaat — niet fataal
		if err != nil && !strings.HasPrefix(cmd, "no ") {
			return output.String(), fmt.Errorf("command %q failed: %w", cmd, err)
		}
	}

	return output.String(), nil
}

// DisablePNP connects to a switch and disables Plug-and-Play (PNP).
// CBS350 commands:
//
//	configure
//	no pnp enable
//	end
//	write memory
func DisablePNP(host string, creds Credentials, timeout time.Duration) (string, error) {
	client, err := Connect(host, creds.Username, creds.Password, timeout)
	if err != nil {
		return "", fmt.Errorf("ssh connect: %w", err)
	}
	defer client.Close()

	commands := []string{
		"configure",
		"no pnp enable",
		"end",
		"write memory",
	}

	var output strings.Builder
	for _, cmd := range commands {
		out, err := client.Run(cmd, 10*time.Second)
		if err != nil {
			return output.String(), fmt.Errorf("command %q failed: %w", cmd, err)
		}
		output.WriteString(fmt.Sprintf("> %s\n%s\n", cmd, out))
	}

	return output.String(), nil
}

// RunShowCommand connects to a switch and executes a read-only show command.
func RunShowCommand(host string, creds Credentials, command string, timeout time.Duration) (string, error) {
	// Safety check: only allow show commands
	cmd := strings.TrimSpace(command)
	if !strings.HasPrefix(strings.ToLower(cmd), "show") {
		return "", fmt.Errorf("only 'show' commands are allowed, got: %q", cmd)
	}

	client, err := Connect(host, creds.Username, creds.Password, timeout)
	if err != nil {
		return "", fmt.Errorf("ssh connect: %w", err)
	}
	defer client.Close()

	out, err := client.Run(cmd, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("command %q failed: %w", cmd, err)
	}

	return out, nil
}

// ConfigureVLAN sets a port to access mode with the specified VLAN.
// CBS350 commands:
//
//	configure
//	interface <interface>
//	switchport mode access
//	switchport access vlan <vlan_id>
//	end
//	write memory
//
// Safety: only allows access port configuration (not trunk).
func ConfigureVLAN(host string, creds Credentials, iface string, vlanID int, timeout time.Duration) (string, error) {
	if vlanID < 1 || vlanID > 4094 {
		return "", fmt.Errorf("invalid VLAN ID %d (must be 1-4094)", vlanID)
	}

	// Validate interface name format (gi1/0/1, fa1/0/1, te1/0/1, etc.)
	ifLower := strings.ToLower(iface)
	validPrefixes := []string{"gi", "fa", "te", "po"}
	valid := false
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(ifLower, prefix) {
			valid = true
			break
		}
	}
	if !valid {
		return "", fmt.Errorf("invalid interface name %q", iface)
	}

	client, err := Connect(host, creds.Username, creds.Password, timeout)
	if err != nil {
		return "", fmt.Errorf("ssh connect: %w", err)
	}
	defer client.Close()

	commands := []string{
		"configure",
		fmt.Sprintf("interface %s", iface),
		"switchport mode access",
		fmt.Sprintf("switchport access vlan %d", vlanID),
		"end",
		"write memory",
	}

	var output strings.Builder
	for _, cmd := range commands {
		out, err := client.Run(cmd, 10*time.Second)
		if err != nil {
			return output.String(), fmt.Errorf("command %q failed: %w", cmd, err)
		}
		output.WriteString(fmt.Sprintf("> %s\n%s\n", cmd, out))
	}

	slog.Info("VLAN configured",
		"host", host,
		"interface", iface,
		"vlan", vlanID,
	)

	return output.String(), nil
}

// ExecuteConfigureAction dispatches a configure trigger to the right handler.
// Returns progress steps that should be reported to the dashboard.
func ExecuteConfigureAction(
	action string,
	sw api.SwitchConfig,
	creds Credentials,
	params map[string]interface{},
	scanID string,
	progress func(api.ScanProgressStep),
) ConfigureResult {
	logger := slog.With("switch", sw.Name, "host", sw.Host, "action", action, "scan_id", scanID)
	sid := sw.ID

	emit := func(step, detail, status string) {
		if progress != nil {
			progress(api.ScanProgressStep{
				ScanID:   scanID,
				SwitchID: &sid,
				Step:     step,
				Detail:   detail,
				Status:   status,
			})
		}
	}

	emit("ssh_connect", fmt.Sprintf("Verbinden met %s (%s)...", sw.Name, sw.Host), "running")

	var output string
	var err error

	switch action {
	case "configure_syslog":
		syslogHost, _ := params["syslog_host"].(string)
		if syslogHost == "" {
			syslogHost = "172.16.0.1"
		}
		syslogLevel, _ := params["syslog_level"].(string)
		if syslogLevel == "" {
			syslogLevel = "4"
		}
		emit("configure_syslog", fmt.Sprintf("Syslog configureren op %s → %s (level %s)", sw.Name, syslogHost, syslogLevel), "running")
		output, err = ConfigureSyslog(sw.Host, creds, sw.Model, syslogHost, syslogLevel, 30*time.Second)

	case "disable_pnp":
		emit("disable_pnp", fmt.Sprintf("PNP uitschakelen op %s", sw.Name), "running")
		output, err = DisablePNP(sw.Host, creds, 30*time.Second)

	case "run_show_command":
		cmd, _ := params["command"].(string)
		if cmd == "" {
			return ConfigureResult{SwitchID: sid, SwitchName: sw.Name, Error: "no command specified"}
		}
		emit("run_command", fmt.Sprintf("%s > %s", sw.Name, cmd), "running")
		output, err = RunShowCommand(sw.Host, creds, cmd, 30*time.Second)

	case "configure_vlan":
		iface, _ := params["interface"].(string)
		vlanFloat, _ := params["vlan_id"].(float64) // JSON numbers are float64
		vlanID := int(vlanFloat)
		if iface == "" || vlanID == 0 {
			return ConfigureResult{SwitchID: sid, SwitchName: sw.Name, Error: "interface and vlan_id required"}
		}
		emit("configure_vlan", fmt.Sprintf("VLAN %d instellen op %s %s", vlanID, sw.Name, iface), "running")
		output, err = ConfigureVLAN(sw.Host, creds, iface, vlanID, 30*time.Second)

	default:
		logger.Warn("unknown configure action", "action", action)
		return ConfigureResult{SwitchID: sid, SwitchName: sw.Name, Error: fmt.Sprintf("unknown action: %s", action)}
	}

	if err != nil {
		logger.Error("configure action failed", "err", err)
		emit("error", fmt.Sprintf("%s MISLUKT: %s", sw.Name, err.Error()), "error")
		return ConfigureResult{SwitchID: sid, SwitchName: sw.Name, Output: output, Error: err.Error()}
	}

	logger.Info("configure action completed", "output_len", len(output))
	emit("switch_done", fmt.Sprintf("%s geconfigureerd", sw.Name), "done")
	return ConfigureResult{SwitchID: sid, SwitchName: sw.Name, Success: true, Output: output}
}
