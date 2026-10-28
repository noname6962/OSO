# Buduje paczkę Windows x64 do `artifacts/service`. Dołącza runtime .NET, więc na maszynie uruchamiającej gotową paczkę nie trzeba go instalować osobno.

<#
.SYNOPSIS
Build the Windows x64 application and include the .NET runtime needed to run it.
.DESCRIPTION
Uses the checked-in package lockfiles. The resulting artifacts/service folder is
the input to Install-Service.ps1; the destination VM needs no separate .NET runtime.
#>
[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\service'))
$ErrorActionPreference = 'Stop'
# Resolve project paths relative to this script, regardless of the caller's current directory.
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    # External commands do not automatically throw on a nonzero exit code; check it explicitly below.
    & dotnet publish '.\src\Oso.Service\Oso.Service.csproj' -c Release -r win-x64 --self-contained true -p:RestoreLockedMode=true -o $OutputDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
} finally { Pop-Location }
