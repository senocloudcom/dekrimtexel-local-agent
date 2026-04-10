# install.ps1 — Download + install de dekrimtexel local-agent op Windows.
#
# Usage:
#   irm https://raw.githubusercontent.com/senocloudcom/dekrimtexel-local-agent/main/scripts/install.ps1 | iex
#
# Of met parameters (dan moet je hem eerst als file pakken):
#   $env:PAIRING_CODE = "ABCD-EF12"
#   $env:TENANT = "dekrim"
#   $env:SERVER = "https://ping.senocloud.com"
#   irm https://raw.githubusercontent.com/senocloudcom/dekrimtexel-local-agent/main/scripts/install.ps1 | iex

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

# === Config ===
$Repo         = "senocloudcom/dekrimtexel-local-agent"
$BinaryName   = "local-agent-windows-amd64.exe"
$InstallPath  = "$env:ProgramFiles\dekrimtexel-agent"
$InstallExe   = "$InstallPath\local-agent.exe"
$ConfigDir    = "$env:ProgramData\dekrimtexel-agent"
$ServiceName  = "dekrimtexel-local-agent"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  dekrimtexel local-agent installer" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# === Check admin ===
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "FOUT: dit script vereist Administrator rechten." -ForegroundColor Red
    Write-Host "Open een PowerShell als Administrator en probeer opnieuw." -ForegroundColor Red
    exit 1
}

# === Determine version ===
$Version = $env:AGENT_VERSION
if (-not $Version) {
    Write-Host "Ophalen laatste release..." -ForegroundColor Gray
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        $Version = $release.tag_name
    } catch {
        Write-Host "Kan latest release niet ophalen (is er al een release?). Gebruik -e AGENT_VERSION=v0.1.0 om te forceren." -ForegroundColor Red
        exit 1
    }
}
Write-Host "Versie: $Version" -ForegroundColor Green

# === Download binary ===
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$BinaryName"
$TempExe = "$env:TEMP\local-agent-download.exe"

Write-Host "Downloaden van $DownloadUrl..." -ForegroundColor Gray
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempExe -UseBasicParsing
} catch {
    Write-Host "FOUT bij downloaden: $_" -ForegroundColor Red
    exit 1
}

$sizeMB = [math]::Round((Get-Item $TempExe).Length / 1MB, 1)
Write-Host "Download OK ($sizeMB MB)" -ForegroundColor Green

# === Stop bestaande service indien actief ===
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Stoppen bestaande service..." -ForegroundColor Gray
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# === Installeer binary ===
Write-Host "Installeren in $InstallPath..." -ForegroundColor Gray
New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
Move-Item -Path $TempExe -Destination $InstallExe -Force
New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
New-Item -Path "$ConfigDir\logs" -ItemType Directory -Force | Out-Null
Write-Host "Binary geinstalleerd: $InstallExe" -ForegroundColor Green

# === Pair (als env vars gezet, anders interactief prompten) ===
$PairingCode = $env:PAIRING_CODE
$TenantId    = $env:TENANT
$Server      = $env:SERVER

if (-not $PairingCode) {
    Write-Host ""
    Write-Host "Heb je al een koppelcode? Genereer er een in het dashboard:" -ForegroundColor Yellow
    Write-Host "  Admin -> Agents -> 'Koppelcode genereren' (type: local)" -ForegroundColor Yellow
    Write-Host ""
    $PairingCode = Read-Host "Koppelcode (bijv. ABCD-EF12)"
}
if (-not $TenantId) {
    $TenantId = Read-Host "Tenant ID (bijv. 'dekrim')"
}
if (-not $Server) {
    $Server = Read-Host "Dashboard URL (bijv. https://ping.senocloud.com)"
}

Write-Host ""
Write-Host "Pairing met dashboard..." -ForegroundColor Gray
& $InstallExe pair --code $PairingCode --tenant $TenantId --server $Server
if ($LASTEXITCODE -ne 0) {
    Write-Host "Pairing mislukt (exit code $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

# === Secret key ===
Write-Host ""
Write-Host "Haal de agent secret key op in het dashboard:" -ForegroundColor Yellow
Write-Host "  Admin -> Agents -> 'Agent secret key tonen'" -ForegroundColor Yellow
Write-Host ""
$SecretKey = Read-Host "Plak de 64-character hex key"

if ($SecretKey) {
    & $InstallExe set-secret --key $SecretKey
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Secret opslaan mislukt" -ForegroundColor Red
        exit 1
    }
}

# === Windows Service registreren (placeholder tot fase C-eta) ===
# Voor nu: start als geplande taak die altijd draait.
# In fase C-eta wordt dit een echte Windows Service via kardianos/service.
Write-Host ""
Write-Host "Service configureren..." -ForegroundColor Gray

# Verwijder eventuele oude taak
Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute $InstallExe -Argument "run"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $ServiceName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Ping platform local monitoring agent" | Out-Null

Start-ScheduledTask -TaskName $ServiceName
Write-Host "Service gestart als scheduled task '$ServiceName'" -ForegroundColor Green

# === Klaar ===
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Installatie voltooid" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Commands:" -ForegroundColor Cyan
Write-Host "  Status:   Get-ScheduledTask -TaskName $ServiceName" -ForegroundColor Gray
Write-Host "  Logs:     Get-Content $ConfigDir\logs\agent.log -Tail 50 -Wait" -ForegroundColor Gray
Write-Host "  Stop:     Stop-ScheduledTask -TaskName $ServiceName" -ForegroundColor Gray
Write-Host "  Start:    Start-ScheduledTask -TaskName $ServiceName" -ForegroundColor Gray
Write-Host "  Uninstall: irm https://raw.githubusercontent.com/$Repo/main/scripts/uninstall.ps1 | iex" -ForegroundColor Gray
Write-Host ""
Write-Host "Check in het dashboard: Admin -> Agents. De agent zou nu online moeten zijn." -ForegroundColor Cyan
Write-Host ""
