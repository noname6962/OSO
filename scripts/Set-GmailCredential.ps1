<#
.SYNOPSIS
Prompt for a Gmail App Password and save it encrypted for the local Windows service.
.DESCRIPTION
Uses machine-bound Windows DPAPI and restricts file access to SYSTEM/Administrators.
No password is written to JSON or source. Use -ReplaceExisting deliberately when rotating it.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$DataDirectory = (Join-Path $env:ProgramData 'OSO'), [switch]$ReplaceExisting)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'PrivateAcl.ps1')
Add-Type -AssemblyName System.Security
if (-not (Test-Path -LiteralPath $DataDirectory)) {
    New-Item -ItemType Directory -Path $DataDirectory | Out-Null
}
# The ownership marker prevents this script from changing permissions on an unrelated nonempty folder.
$marker = Join-Path $DataDirectory '.oso-state-directory'
if (-not (Test-Path -LiteralPath $marker) -and @(Get-ChildItem -LiteralPath $DataDirectory -Force).Count -gt 0) {
    throw 'Data directory contains existing files and is not managed by OSO. Choose a dedicated empty directory.'
}
# Do not replace an existing credential unless the caller explicitly requested rotation.
$path = Join-Path $DataDirectory 'gmail-password.bin'
if ((Test-Path -LiteralPath $path) -and -not $ReplaceExisting) {
    throw 'Credential already exists. Use -ReplaceExisting to deliberately rotate it.'
}
# Replace the whole DACL, including any pre-existing explicit grants.
Set-OsoPrivateAcl -Path $DataDirectory -Directory
Set-Content -LiteralPath $marker -Value 'OSO state directory' -Encoding ASCII
# Read without echoing the password. Plaintext is needed briefly to create the encrypted byte payload.
$secure = Read-Host 'Gmail App Password (not your normal account password)' -AsSecureString
$pointer = [IntPtr]::Zero
$bytes = $null
try {
    # BSTR is an unmanaged string buffer; retain its pointer so it can be cleared in finally.
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer).Replace(' ', '')
    if ([string]::IsNullOrWhiteSpace($plain)) { throw 'App Password cannot be empty.' }
    $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
    # LocalMachine lets the service decrypt on this VM even though setup ran as an administrator.
    # Encryption is not account-specific here, so the restrictive file ACL is also necessary.
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($path, $encrypted)
    Set-OsoPrivateAcl -Path $path
    Write-Host 'Encrypted Gmail credential saved. No password was written to configuration.'
} finally {
    # Clear byte/unmanaged buffers even on failure. Managed plaintext strings cannot be explicitly wiped.
    if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $plain = $null
    $secure.Dispose()
}
