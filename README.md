# dekrimtexel-local-agent

Go-based local monitoring agent for the **Ping platform** (ICTexel/SenoCloud MSP monitoring).

Runs on the customer side (Windows PC, Linux VM, Raspberry Pi) with direct LAN access to network
equipment. Handles switch SSH scans, ping checks, syslog UDP reception, and switch write actions
(configure syslog, disable PnP, run show commands).

## Design

Follows the modern "agent installer" pattern used by Datadog, Prometheus node_exporter, Zabbix
Agent 2, and Grafana Alloy:

- **Single static binary** — no runtime, no dependencies, cross-compiled per platform
- **Outbound HTTPS only** — talks to `https://ping.senocloud.com` API; no inbound firewall rules needed
- **No direct database access** — all data flows through the platform's REST API
- **OS-level secret storage** — DPAPI (Windows) / kernel keyring (Linux), not plain text files
- **Windows Service / systemd unit** — auto-start, restart on crash

## Status

**Very early (2026-04-10)**. Fase C-alpha + C-beta being built. See
`dekrimtexel-dashboard/docs/SPEC-local-agent.md` for the canonical spec and roadmap.

## Specification

The canonical spec lives in the **dashboard** repository at:
```
senocloudcom/dekrimtexel-dashboard
  docs/ARCHITECTURE.md        (infrastructure overview)
  docs/SPEC-local-agent.md    (this agent's full spec)
```

## Quickstart (development)

```bash
# Clone
git clone https://github.com/senocloudcom/dekrimtexel-local-agent
cd dekrimtexel-local-agent

# Build for your OS
make build

# Run tests (coming later)
# make test

# Cross-compile for all platforms
make build-all
```

## Install on Windows monitoring PC

```powershell
# 1. Download latest release
Invoke-WebRequest `
  https://github.com/senocloudcom/dekrimtexel-local-agent/releases/latest/download/local-agent-windows-amd64.exe `
  -OutFile C:\Windows\Temp\local-agent.exe

# 2. Pair with dashboard
C:\Windows\Temp\local-agent.exe pair `
  --code ABCD-EF12 `
  --tenant dekrim `
  --server https://ping.senocloud.com

# 3. Set agent secret key (get from dashboard Admin -> Agents -> "Agent secret key tonen")
C:\Windows\Temp\local-agent.exe set-secret --key <64-hex-char-key>

# 4. Test scan
C:\Windows\Temp\local-agent.exe scan

# 5. Install as Windows Service
C:\Windows\Temp\local-agent.exe install
```

## Architecture

See the full [ARCHITECTURE.md](../dekrimtexel-dashboard/docs/ARCHITECTURE.md) and
[SPEC-local-agent.md](../dekrimtexel-dashboard/docs/SPEC-local-agent.md) in the dashboard repo.

## License

Proprietary - SenoCloud / ICTexel.
