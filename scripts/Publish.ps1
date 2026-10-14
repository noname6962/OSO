[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\service'))
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    & dotnet test '.\tests\Oso.Tests\Oso.Tests.csproj' -c Release -p:RestoreLockedMode=true
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed; publish cancelled.' }
    & dotnet publish '.\src\Oso.Service\Oso.Service.csproj' -c Release -r win-x64 --self-contained true -p:RestoreLockedMode=true -o $OutputDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
} finally { Pop-Location }
