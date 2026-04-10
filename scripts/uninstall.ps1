# uninstall.ps1 — Verwijdert de dekrimtexel local-agent van Windows.
#
# Usage:
#   irm https://raw.githubusercontent.com/senocloudcom/dekrimtexel-local-agent/main/scripts/uninstall.ps1 | iex

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'

$InstallPath = "$env:ProgramFiles\dekrimtexel-agent"
$ConfigDir   = "$env:ProgramData\dekrimtexel-agent"
$ServiceName = "dekrimtexel-local-agent"

Write-Host ""
Write-Host "dekrimtexel local-agent uninstaller" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "FOUT: Administrator rechten vereist." -ForegroundColor Red
    exit 1
}

# Stop scheduled task
$task = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "Scheduled task stoppen en verwijderen..." -ForegroundColor Gray
    Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
    Write-Host "Scheduled task verwijderd" -ForegroundColor Green
}

# Stop Windows Service (voor fase C-eta als we daarnaar overgaan)
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Windows service stoppen..." -ForegroundColor Gray
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    Write-Host "Windows service verwijderd" -ForegroundColor Green
}

# Remove files
if (Test-Path $InstallPath) {
    Write-Host "Binary verwijderen uit $InstallPath..." -ForegroundColor Gray
    Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Binary verwijderd" -ForegroundColor Green
}

# Ask about config / secrets
$removeConfig = Read-Host "Ook config en secret verwijderen uit ${ConfigDir}? (y/n)"
if ($removeConfig -eq 'y') {
    if (Test-Path $ConfigDir) {
        Remove-Item -Path $ConfigDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Config verwijderd" -ForegroundColor Green
    }
} else {
    Write-Host "Config bewaard in $ConfigDir (verwijder handmatig als gewenst)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Uninstall voltooid." -ForegroundColor Green
Write-Host ""
