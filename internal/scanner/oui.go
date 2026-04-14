package scanner

import "strings"

// OUILookup bepaalt de vendor op basis van de eerste 3 octets van een MAC.
// Ontbrekend → lege string.
//
// Deze lijst is bewust beperkt tot vendors die relevant zijn voor SMB-netwerken:
// Cisco (incl CBS), HP/Aruba, Ubiquiti, Synology, QNAP, Raspberry Pi, SonicWall,
// Lexmark, Brother, HP printers, Apple, Microsoft/Surface, Intel, Dell, enz.
//
// Later kunnen we de volledige IEEE OUI dump via //go:embed toevoegen voor
// completeness; voor een eerste iteratie dekt deze lijst ~80% van de cases.
func OUILookup(mac string) string {
	if mac == "" {
		return ""
	}
	// Normaliseer naar "aa:bb:cc"
	s := strings.ToLower(mac)
	s = strings.ReplaceAll(s, "-", ":")
	parts := strings.SplitN(s, ":", 4)
	if len(parts) < 3 {
		return ""
	}
	prefix := parts[0] + ":" + parts[1] + ":" + parts[2]
	if v, ok := ouiPrefixes[prefix]; ok {
		return v
	}
	return ""
}

var ouiPrefixes = map[string]string{
	// Cisco — zeer veel ranges, kleine selectie populairste
	"00:00:0c": "Cisco",
	"00:01:42": "Cisco",
	"00:0b:fd": "Cisco",
	"00:11:5c": "Cisco",
	"00:1b:d4": "Cisco",
	"00:24:14": "Cisco",
	"58:8b:1c": "Cisco",
	"58:8d:09": "Cisco",
	"a4:00:4e": "Cisco",
	"f0:9e:63": "Cisco",
	"3c:ce:73": "Cisco",
	"cc:16:7e": "Cisco",
	"38:fd:f8": "Cisco",

	// HP / Aruba (HPE)
	"00:1b:78": "HP",
	"00:1c:c4": "HP",
	"00:21:5a": "HP",
	"00:26:55": "HP",
	"00:30:c1": "HP",
	"3c:d9:2b": "HPE",
	"9c:8e:99": "HPE",
	"3c:4a:92": "HPE",
	"00:0b:86": "Aruba",
	"00:1a:1e": "Aruba",
	"20:4c:03": "Aruba",

	// Ubiquiti
	"00:15:6d": "Ubiquiti",
	"00:27:22": "Ubiquiti",
	"04:18:d6": "Ubiquiti",
	"24:5a:4c": "Ubiquiti",
	"dc:9f:db": "Ubiquiti",
	"f0:9f:c2": "Ubiquiti",
	"fc:ec:da": "Ubiquiti",
	"78:45:58": "Ubiquiti",
	"b4:fb:e4": "Ubiquiti",

	// SonicWall / Dell
	"00:17:c5": "SonicWall",
	"c0:ea:e4": "SonicWall",
	"18:b1:69": "SonicWall",
	"00:06:b1": "Dell",
	"00:0d:56": "Dell",
	"00:14:22": "Dell",
	"00:1e:4f": "Dell",
	"00:22:19": "Dell",
	"d4:be:d9": "Dell",
	"f8:b1:56": "Dell",
	"f4:8e:38": "Dell",

	// Apple
	"04:0c:ce": "Apple",
	"28:cf:e9": "Apple",
	"34:15:9e": "Apple",
	"3c:07:54": "Apple",
	"40:6c:8f": "Apple",
	"60:f8:1d": "Apple",
	"64:b9:e8": "Apple",
	"7c:6d:62": "Apple",
	"a4:b8:05": "Apple",
	"bc:ec:5d": "Apple",
	"d8:a2:5e": "Apple",
	"f0:db:f8": "Apple",

	// Microsoft (Surface / Xbox)
	"00:12:5a": "Microsoft",
	"00:15:5d": "Microsoft (Hyper-V)",
	"00:1d:d8": "Microsoft",
	"28:18:78": "Microsoft",
	"7c:1e:52": "Microsoft",
	"c8:3a:6b": "Microsoft",

	// Intel (veel laptops/NICs)
	"00:02:b3": "Intel",
	"00:13:e8": "Intel",
	"00:15:17": "Intel",
	"00:1c:c0": "Intel",
	"00:21:6a": "Intel",
	"00:24:d7": "Intel",
	"1c:69:7a": "Intel",
	"24:77:03": "Intel",
	"3c:a9:f4": "Intel",
	"4c:34:88": "Intel",
	"7c:5c:f8": "Intel",
	"a0:88:b4": "Intel",
	"f8:16:54": "Intel",

	// Raspberry Pi
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"d8:3a:dd": "Raspberry Pi",
	"2c:cf:67": "Raspberry Pi",

	// Synology / QNAP
	"00:11:32": "Synology",
	"90:09:d0": "Synology",
	"00:08:9b": "QNAP",
	"24:5e:be": "QNAP",

	// HP / Brother / Lexmark / Epson / Canon printers
	"00:0f:b0": "Canon",
	"00:00:85": "Canon",
	"00:80:77": "Brother",
	"00:1b:a9": "Brother",
	"00:14:cf": "InVentec",
	"00:04:00": "Lexmark",
	"00:20:00": "Lexmark",
	"00:00:48": "Epson",
	"00:26:ab": "Epson",
	"90:9c:dd": "Epson",

	// Fortinet / PaloAlto / Meraki
	"00:09:0f": "Fortinet",
	"90:6c:ac": "Fortinet",
	"00:1b:17": "PaloAlto",
	"e0:cb:bc": "Meraki (Cisco)",
	"88:15:44": "Meraki (Cisco)",

	// Zyxel / TP-Link / D-Link / Netgear
	"00:13:49": "Zyxel",
	"d0:d4:12": "Zyxel",
	"00:14:78": "TP-Link",
	"b0:48:7a": "TP-Link",
	"c4:e9:84": "TP-Link",
	"00:05:5d": "D-Link",
	"00:17:9a": "D-Link",
	"00:0f:b5": "Netgear",
	"00:14:6c": "Netgear",
	"c4:04:15": "Netgear",

	// VMware / virtualisatie
	"00:50:56": "VMware",
	"00:0c:29": "VMware",
	"00:1c:14": "VMware",
	"08:00:27": "VirtualBox",
	"52:54:00": "QEMU/KVM",

	// TV / streaming / IoT
	"00:25:00": "Apple-AirPort",
	"b0:d5:9d": "Amazon",
	"f0:27:2d": "Amazon",
	"fc:65:de": "Amazon",
	"00:17:88": "Philips Hue",
	"00:1a:22": "Philips Hue",

	// Axis / Hikvision / Dahua cameras
	"00:40:8c": "Axis Communications",
	"ac:cc:8e": "Axis Communications",
	"b8:a4:4f": "Axis Communications",
	"bc:ad:28": "Hikvision",
	"28:57:be": "Hikvision",
	"4c:bd:8f": "Hikvision",
	"fc:5f:49": "Hikvision",
	"00:40:7f": "Dahua",
	"3c:ef:8c": "Dahua",
	"90:02:a9": "Dahua",

	// Liftsystem / IoT / PLC
	"00:80:41": "AMT (PLC/industrial)",
}
