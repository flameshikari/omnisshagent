[CmdletBinding()]
param(
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$output = Join-Path $repositoryRoot "dist\OmniSSHAgent-debug.exe"
$previousGOOS, $previousGOARCH = $env:GOOS, $env:GOARCH
Push-Location $repositoryRoot
try {
    New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force | Out-Null
    $env:GOOS = "windows"
    $env:GOARCH = $Architecture
    go build "-gcflags=all=-N -l" -o $output ./cmd/omnisshagent
    if ($LASTEXITCODE -ne 0) { throw "Debug build failed." }
    Write-Host "Built $output"
} finally {
    $env:GOOS, $env:GOARCH = $previousGOOS, $previousGOARCH
    Pop-Location
}
