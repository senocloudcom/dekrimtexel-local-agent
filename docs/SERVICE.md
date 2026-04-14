# Agent als Windows service

Vanaf v0.1.0-alpha35 kan de `local-agent.exe` zichzelf registreren als native
Windows service — geen NSSM, WinSW of Npcap driver nodig. 1 binary, 1 command.

## Eerste installatie

In **PowerShell als administrator**:

```powershell
# 1. Stop een eventueel lopend handmatig proces
Stop-Process -Name local-agent -Force -ErrorAction SilentlyContinue

# 2. Plaats de nieuwe binary in Program Files
$dir = "C:\Program Files\dekrimtexel-agent"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item .\local-agent.exe "$dir\local-agent.exe" -Force

# 3. Registreer service
& "$dir\local-agent.exe" install

# 4. Start
Start-Service DekrimLocalAgent

# 5. Controleer
Get-Service DekrimLocalAgent
Get-Content C:\ProgramData\dekrimtexel-agent\agent.log -Tail 20
```

De service is nu geregistreerd met:
- **Name**: `DekrimLocalAgent`
- **Start**: Automatic (start bij boot)
- **Account**: `LocalSystem` (nodig voor UDP 1514 syslog bind + outbound TCP)
- **Recovery**: herstart na 5s / 30s / 60s bij crash

## Release / upgrade

Elke nieuwe alpha-tag vereist alleen een binary-swap en service-restart:

```powershell
# Als admin
Stop-Service DekrimLocalAgent
Copy-Item .\local-agent.exe "C:\Program Files\dekrimtexel-agent\local-agent.exe" -Force
Start-Service DekrimLocalAgent
Get-Content C:\ProgramData\dekrimtexel-agent\agent.log -Tail 20
```

> **Waarom stop + start en niet `Restart-Service`?**
> `Restart-Service` sluit file handles soms niet snel genoeg voor
> `Copy-Item`, wat een "file in use" error geeft. Stop + Copy + Start is
> deterministisch.

### PowerShell script voor snelle upgrades (aanbevolen)

Plaats dit als `C:\Program Files\dekrimtexel-agent\update-agent.ps1`:

```powershell
param([string]$Tag = "latest")

$ErrorActionPreference = "Stop"
$dir = "C:\Program Files\dekrimtexel-agent"
$dest = "$dir\local-agent.exe"
$repo = "senocloudcom/dekrimtexel-local-agent"

if ($Tag -eq "latest") {
  Write-Host "Fetching latest release tag..."
  $json = curl.exe -sSL "https://api.github.com/repos/$repo/releases/latest"
  $Tag = ($json | ConvertFrom-Json).tag_name
}
$url = "https://github.com/$repo/releases/download/$Tag/local-agent-windows-amd64.exe"

Write-Host "Upgrade naar $Tag..."
Stop-Service DekrimLocalAgent -Force -ErrorAction SilentlyContinue
Stop-Process -Name local-agent -Force -ErrorAction SilentlyContinue
Start-Sleep 2

curl.exe -sSL -o $dest $url
if (-not (Test-Path $dest)) { throw "Download mislukt" }
& $dest version

Start-Service DekrimLocalAgent
Start-Sleep 5
Get-Service DekrimLocalAgent | Format-List Name, Status, StartType
Get-Content "C:\ProgramData\dekrimtexel-agent\logs\agent.log" -Tail 30
```

Gebruik:
```powershell
.\update-agent.ps1                    # laatste release
.\update-agent.ps1 -Tag v0.1.0-alpha35 # specifieke versie
```

## Wijziging in service-definitie

Als je de **service-args of executable-pad** wilt wijzigen (zelden), dan:

```powershell
Stop-Service DekrimLocalAgent
& "C:\Program Files\dekrimtexel-agent\local-agent.exe" uninstall
& "C:\Program Files\dekrimtexel-agent\local-agent.exe" install
Start-Service DekrimLocalAgent
```

Voor gewone binary updates is dit **niet** nodig — de service-definitie
bevat alleen `executable path + "service" arg`, die blijven gelijk.

## Logs

- **File**: `C:\ProgramData\dekrimtexel-agent\agent.log` (append-only,
  rotatie niet automatisch — knip periodiek bij indien nodig)
- **Windows Event Log**: bevat alleen service-start/stop events (SCM), niet
  de agent-logs zelf. Kijk naar het logbestand voor inhoudelijke info.

## Troubleshooting

**Service start niet, meteen stopped**
1. Run `local-agent.exe run` interactief — welke error verschijnt?
2. Meestal: ontbrekende `config.json` (niet gepaird) of `secret` niet gezet

**"Access denied" bij install**
- PowerShell moet als admin draaien. Rechtermuis → "Run as administrator"

**Service Running maar geen heartbeat in DB**
- Check logbestand op netwerkfouten (firewall, DNS)
- Check `SERVER_URL` in `C:\ProgramData\dekrimtexel-agent\config.json`

**Syslog UDP 1514 werkt niet**
- Firewall regel toevoegen:
  ```powershell
  New-NetFirewallRule -DisplayName "Dekrim Syslog" `
    -Direction Inbound -Protocol UDP -LocalPort 1514 -Action Allow
  ```

**Service verwijderen**
```powershell
Stop-Service DekrimLocalAgent
& "C:\Program Files\dekrimtexel-agent\local-agent.exe" uninstall
# Daarna mag je de files verwijderen:
Remove-Item "C:\Program Files\dekrimtexel-agent" -Recurse -Force
Remove-Item "C:\ProgramData\dekrimtexel-agent" -Recurse -Force
```
