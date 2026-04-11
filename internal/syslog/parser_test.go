package syslog

import "testing"

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantSev    string
		wantLevel  int
		wantMnem   string
		wantIface  string
		wantHost   string
		wantFac    string
		wantMsgSub string
	}{
		{
			name:       "cbs350 structured warning with interface",
			raw:        "<warning> Feb 19 15:23:01 Golfbaan-Switch2: %STP-W-PORTSTATUS: gi1/0/15: STP status Forwarding",
			wantSev:    "warning",
			wantLevel:  4,
			wantMnem:   "PORTSTATUS",
			wantIface:  "gi1/0/15",
			wantHost:   "Golfbaan-Switch2",
			wantFac:    "STP",
			wantMsgSub: "STP status Forwarding",
		},
		{
			name:       "cbs350 error bpduguard",
			raw:        "<error> Feb 19 15:23:01 Golfbaan-Switch2: %MSTP-E-BPDU_GUARD: gi1/0/15 put in errdisable",
			wantSev:    "error",
			wantLevel:  3,
			wantMnem:   "BPDU_GUARD",
			wantIface:  "gi1/0/15",
			wantHost:   "Golfbaan-Switch2",
			wantFac:    "MSTP",
			wantMsgSub: "errdisable",
		},
		{
			name:      "numeric priority link up",
			raw:       "<187>Apr 11 14:30:00 KRIM-CORE-1: %LINK-W-Down: gi1/0/1 is down",
			wantSev:   "error",
			wantLevel: 3,
			wantMnem:  "Down",
			wantIface: "gi1/0/1",
			wantHost:  "KRIM-CORE-1",
			wantFac:   "LINK",
		},
		{
			name:       "no structured part falls back to info",
			raw:        "Some random string without any structure",
			wantSev:    "info",
			wantLevel:  6,
			wantMsgSub: "random string",
		},
		{
			name:      "empty string is safe",
			raw:       "",
			wantSev:   "info",
			wantLevel: 6,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseMessage(tc.raw)
			// The numeric-priority test uses pri=187: 187%8=3 (error), 187/8=23 (local7).
			// After the structured body %LINK-W-Down is parsed the severity letter
			// 'W' would normally set level=4, but since the letter-case ('W') is Warning
			// we actually override: check what we really expect.
			if tc.name == "numeric priority link up" {
				// Structured overrides numeric: W → warning/4
				if got.Severity != "warning" || got.SeverityLevel != 4 {
					t.Errorf("sev/level = %s/%d, want warning/4 (structured overrides numeric)", got.Severity, got.SeverityLevel)
				}
			} else {
				if got.Severity != tc.wantSev {
					t.Errorf("severity = %q, want %q", got.Severity, tc.wantSev)
				}
				if got.SeverityLevel != tc.wantLevel {
					t.Errorf("severity_level = %d, want %d", got.SeverityLevel, tc.wantLevel)
				}
			}
			if tc.wantMnem != "" && got.Mnemonic != tc.wantMnem {
				t.Errorf("mnemonic = %q, want %q", got.Mnemonic, tc.wantMnem)
			}
			if tc.wantIface != "" && got.Interface != tc.wantIface {
				t.Errorf("interface = %q, want %q", got.Interface, tc.wantIface)
			}
			if tc.wantHost != "" && got.SwitchName != tc.wantHost {
				t.Errorf("switch_name = %q, want %q", got.SwitchName, tc.wantHost)
			}
			if tc.wantFac != "" && got.Facility != tc.wantFac {
				t.Errorf("facility = %q, want %q", got.Facility, tc.wantFac)
			}
			if tc.wantMsgSub != "" && !contains(got.Message, tc.wantMsgSub) {
				t.Errorf("message = %q, want to contain %q", got.Message, tc.wantMsgSub)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
