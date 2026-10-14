<#
.SYNOPSIS
Install and start the login monitor on the local Windows VM.
.DESCRIPTION
Run in administrator Windows PowerShell 5.1 after publishing the application and
saving a Gmail credential. Copies binaries, writes non-secret local settings,
registers the warning log and Windows Service, and configures restart recovery.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GmailAddress,
    [Parameter(Mandatory = $true)][string]$Recipient,
    [string]$PublishDirectory = (Join-Path $PSScriptRoot '..\artifacts\service'),
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'OSO'),
    [string]$DataDirectory = (Join-Path $env:ProgramData 'OSO')
)
# Stop on PowerShell errors instead of continuing a partly failed installation.
$ErrorActionPreference = 'Stop'
# Dot-sourcing loads the shared permission helper into this script's scope.
. (Join-Path $PSScriptRoot 'PrivateAcl.ps1')
$serviceName = 'OsoLoginMonitor'
# Require plain email addresses; these become the SMTP sender/login and alert recipient.
foreach ($address in @($GmailAddress, $Recipient)) {
    $parsed = New-Object System.Net.Mail.MailAddress($address)
    if ($parsed.Address -ne $address) { throw 'Supply an email address without a display name.' }
}
# Preflight: refuse missing binaries/credentials, an existing service, or copied local configuration.
# This avoids overwriting an existing installation or deploying another user's settings.
$publish = (Resolve-Path -LiteralPath $PublishDirectory).Path
if (-not (Test-Path -LiteralPath (Join-Path $publish 'Oso.Service.exe'))) { throw 'Publish the service first.' }
if (Test-Path -LiteralPath (Join-Path $publish 'appsettings.Local.json')) { throw 'Publish input contains local configuration. Remove it before installation.' }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Service already exists. Stop and uninstall it before replacing binaries.' }
if (-not (Test-Path -LiteralPath (Join-Path $DataDirectory 'gmail-password.bin'))) { throw 'Run Set-GmailCredential.ps1 first.' }
if (-not (Test-Path -LiteralPath (Join-Path $DataDirectory '.oso-state-directory'))) { throw 'Use a state directory prepared by Set-GmailCredential.ps1.' }
# Only use an empty installation directory; protect it before copying privileged binaries.
if (Test-Path -LiteralPath $InstallDirectory) {
    if (@(Get-ChildItem -LiteralPath $InstallDirectory -Force).Count -gt 0) {
        throw 'Install directory is not empty. Preserve existing files and choose an empty directory.'
    }
} else { New-Item -ItemType Directory -Path $InstallDirectory | Out-Null }
Set-OsoPrivateAcl -Path $InstallDirectory -Directory
Copy-Item -Path (Join-Path $publish '*') -Destination $InstallDirectory -Recurse
# Local overrides contain addresses and paths only. The App Password remains in its encrypted file.
$localConfig = Join-Path $InstallDirectory 'appsettings.Local.json'
@{
    Reporting = @{ DataDirectory = $DataDirectory }
    Smtp = @{ Username = $GmailAddress; Recipient = $Recipient; PasswordFile = (Join-Path $DataDirectory 'gmail-password.bin') }
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $localConfig -Encoding UTF8
# Event Log writes select a source; Windows maps that source to the registered log.
# Refuse a source already registered to another log rather than redirecting it silently.
$source = 'OsoLoginMonitor'
$logName = 'OSO-Warnings'
if ([Diagnostics.EventLog]::SourceExists($source)) {
    if ([Diagnostics.EventLog]::LogNameFromSourceName($source, '.') -ne $logName) { throw 'Event source already belongs to another log.' }
} else { New-EventLog -LogName $logName -Source $source }
# Run the application's own local access/configuration checks before registering the service.
# This does not authenticate Gmail or prove that login auditing is enabled.
$exe = Join-Path $InstallDirectory 'Oso.Service.exe'
& $exe --validate-config
if ($LASTEXITCODE -ne 0) { throw 'Configuration/access validation failed. Service was not installed.' }
# LocalSystem is used for the MVP's Security-log access. Keep these directories administrator-controlled.
New-Service -Name $serviceName -BinaryPathName ('"' + $exe + '"') -DisplayName 'OSO Login Monitor' -StartupType Automatic -Description 'Local Windows login monitoring and rule-based alerts.' | Out-Null
# Reset the failure counter after one day; retry restarts after 15, 30 and 60 seconds.
# The action delays are milliseconds, while reset= uses seconds.
& sc.exe failure $serviceName reset= 86400 actions= restart/15000/restart/30000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not configure service recovery.' }
# Apply recovery to reported service failures as well as process crashes.
& sc.exe failureflag $serviceName 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not configure non-crash service recovery.' }
Start-Service -Name $serviceName
Write-Host 'Service installed and started. Follow docs/windows-validation.md to verify actual collection and Gmail delivery.'
