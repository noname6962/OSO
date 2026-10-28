# Zatrzymuje usługę i usuwa jej rejestrację. Zostawia pliki aplikacji, ostrzeżenia, konfigurację, hasło i oczekujące alerty.

<#
.SYNOPSIS
Stop the monitor and remove its Windows Service registration.
.DESCRIPTION
Preserves application files, Windows warning logs, credentials and queued deliveries
so they remain available for investigation or a subsequent reinstall.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$name = 'OsoLoginMonitor'
$service = Get-Service -Name $name -ErrorAction SilentlyContinue
# Treat an already absent service as a successful no-op.
if ($null -ne $service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $name }
    # Remove only the service registration, not the Event Log source or persistent files.
    & sc.exe delete $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove service registration.' }
}
Write-Host 'Service registration removed. Warning logs, credentials, outbox and installation files are preserved.'
