// Package syslog parses and receives Cisco CBS350 syslog messages.
//
// CBS350 format:
//
//	<priority>timestamp hostname: %FACILITY-SEVERITY-MNEMONIC: message
//
// Example:
//
//	<warning> Feb 19 15:23:01 Golfbaan-Switch2: %STP-W-PORTSTATUS: gi1/0/15: STP status Forwarding
//	<error>   Feb 19 15:23:01 Golfbaan-Switch2: %MSTP-E-BPDU_GUARD: gi1/0/15 put in errdisable
//
// Port van tools/syslog_parser.py uit de Python legacy agent.
package syslog

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RFC 5424 severity levels
var severityMap = map[int]string{
	0: "emergency",
	1: "alert",
	2: "critical",
	3: "error",
	4: "warning",
	5: "notice",
	6: "info",
	7: "debug",
}

// CBS350 severity letter → level
var cbs350Severity = map[byte]int{
	'E': 3, // Error
	'W': 4, // Warning
	'N': 5, // Notice
	'I': 6, // Info
	'D': 7, // Debug
	'A': 1, // Alert
	'C': 2, // Critical
}

// Priority text → severity level (CBS350 stuurt soms tekst ipv nummer)
var priorityText = map[string]int{
	"emergency": 0,
	"alert":     1,
	"critical":  2,
	"error":     3,
	"warning":   4,
	"notice":    5,
	"info":      6,
	"debug":     7,
}

var facilities = map[int]string{
	0: "kern", 1: "user", 2: "mail", 3: "daemon",
	4: "auth", 5: "syslog", 6: "lpr", 7: "news",
	8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
	16: "local0", 17: "local1", 18: "local2", 19: "local3",
	20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

var (
	interfaceRe    = regexp.MustCompile(`\b(gi|te|fa|Gi|Te|Fa|GE|TE)\d+/\d+/\d+\b`)
	structuredRe   = regexp.MustCompile(`%(\w+)-([A-Z])-(\w+):\s*(.*)`)
	priorityNumRe  = regexp.MustCompile(`^<(\d+)>`)
	priorityTextRe = regexp.MustCompile(`^<(\w+)>\s*`)
	timestampRe    = regexp.MustCompile(`^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+`)
)

// ParsedEvent is a parsed syslog message. The listener fills in source_ip
// from the UDP packet separately; the parser never sees network info.
type ParsedEvent struct {
	SwitchName    string
	Facility      string
	Severity      string
	SeverityLevel int
	Mnemonic      string
	Interface     string
	Message       string
	RawMessage    string
	Timestamp     time.Time
}

// ParseMessage parses a raw syslog string from a CBS350 switch. It never
// errors — best effort, falls back to info severity with the raw message.
func ParseMessage(raw string) ParsedEvent {
	raw = strings.TrimSpace(raw)
	result := ParsedEvent{
		Severity:      "info",
		SeverityLevel: 6,
		Message:       raw,
		RawMessage:    raw,
		Timestamp:     time.Now().UTC(),
	}

	msg := raw

	// Priority field
	if loc := priorityNumRe.FindStringSubmatchIndex(msg); loc != nil {
		if pri, err := strconv.Atoi(msg[loc[2]:loc[3]]); err == nil {
			result.SeverityLevel = pri % 8
			result.Facility = facilityName(pri / 8)
			if s, ok := severityMap[result.SeverityLevel]; ok {
				result.Severity = s
			}
		}
		msg = strings.TrimSpace(msg[loc[1]:])
	} else if loc := priorityTextRe.FindStringSubmatchIndex(msg); loc != nil {
		priText := strings.ToLower(msg[loc[2]:loc[3]])
		if lvl, ok := priorityText[priText]; ok {
			result.SeverityLevel = lvl
			result.Severity = priText
		}
		msg = strings.TrimSpace(msg[loc[1]:])
	}

	// Skip timestamp (Mmm DD HH:MM:SS)
	if loc := timestampRe.FindStringIndex(msg); loc != nil {
		msg = msg[loc[1]:]
	}

	// Extract hostname (before first colon)
	if colonIdx := strings.Index(msg, ":"); colonIdx > 0 {
		hostname := strings.TrimSpace(msg[:colonIdx])
		if hostname != "" && !strings.HasPrefix(hostname, "%") && !strings.Contains(hostname, " ") {
			result.SwitchName = hostname
			msg = strings.TrimSpace(msg[colonIdx+1:])
		}
	}

	// Parse structured part: %FACILITY-SEVERITY-MNEMONIC: message
	if m := structuredRe.FindStringSubmatch(msg); m != nil {
		result.Facility = m[1]
		sevLetter := m[2][0]
		result.Mnemonic = m[3]
		if m[4] != "" {
			result.Message = strings.TrimSpace(m[4])
		} else {
			result.Message = msg
		}
		if lvl, ok := cbs350Severity[sevLetter]; ok {
			result.SeverityLevel = lvl
			if s, ok := severityMap[lvl]; ok {
				result.Severity = s
			}
		}
	} else {
		result.Message = msg
	}

	// Extract interface from message (fallback naar volledige msg)
	if iface := interfaceRe.FindString(result.Message); iface != "" {
		result.Interface = iface
	} else if iface := interfaceRe.FindString(msg); iface != "" {
		result.Interface = iface
	}

	return result
}

func facilityName(code int) string {
	if name, ok := facilities[code]; ok {
		return name
	}
	return fmt.Sprintf("facility%d", code)
}
