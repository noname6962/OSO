#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$DataDirectory = (Join-Path $env:ProgramData 'OSO'), [switch]$ReplaceExisting)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PrivateAcl.ps1')
Add-Type -AssemblyName System.Security
if (-not (Test-Path -LiteralPath $DataDirectory)) {
    New-Item -ItemType Directory -Path $DataDirectory | Out-Null
}
$marker = Join-Path $DataDirectory '.oso-state-directory'
if (-not (Test-Path -LiteralPath $marker) -and @(Get-ChildItem -LiteralPath $DataDirectory -Force).Count -gt 0) {
    throw 'Data directory contains existing files and is not managed by OSO. Choose a dedicated empty directory.'
}
$path = Join-Path $DataDirectory 'gmail-password.bin'
if ((Test-Path -LiteralPath $path) -and -not $ReplaceExisting) {
    throw 'Credential already exists. Use -ReplaceExisting to deliberately rotate it.'
}
# Replace the whole DACL, including any pre-existing explicit grants.
Set-OsoPrivateAcl -Path $DataDirectory -Directory
Set-Content -LiteralPath $marker -Value 'OSO state directory' -Encoding ASCII
$secure = Read-Host 'Gmail App Password (not your normal account password)' -AsSecureString
$pointer = [IntPtr]::Zero
$bytes = $null
try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer).Replace(' ', '')
    if ([string]::IsNullOrWhiteSpace($plain)) { throw 'App Password cannot be empty.' }
    $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($path, $encrypted)
    Set-OsoPrivateAcl -Path $path
    Write-Host 'Encrypted Gmail credential saved. No password was written to configuration.'
} finally {
    if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $plain = $null
    $secure.Dispose()
}
