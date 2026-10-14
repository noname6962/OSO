#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$name = 'OsoLoginMonitor'
$service = Get-Service -Name $name -ErrorAction SilentlyContinue
if ($null -ne $service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $name }
    & sc.exe delete $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove service registration.' }
}
Write-Host 'Service registration removed. Warning logs, credentials, outbox and installation files are preserved.'
