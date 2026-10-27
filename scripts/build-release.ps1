[CmdletBinding()]
param(
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64",
    [string]$OutputName = "OmniSSHAgent.exe",
    [string]$Version = "dev",
    [string]$Commit = "unknown",
    [string]$BuildTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([IO.Path]::GetFileName($OutputName) -ne $OutputName -or [string]::IsNullOrWhiteSpace($OutputName)) {
    throw "OutputName must be a file name."
}
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$output = Join-Path (Join-Path $repositoryRoot "dist") $OutputName
$previousGOOS, $previousGOARCH = $env:GOOS, $env:GOARCH
Push-Location $repositoryRoot
try {
    New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force | Out-Null
    $env:GOOS = "windows"
    $env:GOARCH = $Architecture
    $ldflags = "-s -w -H=windowsgui -X github.com/masahide/OmniSSHAgent/internal/cli.Version=$Version -X github.com/masahide/OmniSSHAgent/internal/cli.Commit=$Commit -X github.com/masahide/OmniSSHAgent/internal/cli.BuildTime=$BuildTime"
    go build -trimpath "-ldflags=$ldflags" -o $output ./cmd/omnisshagent
    if ($LASTEXITCODE -ne 0) { throw "Release build failed." }
    Write-Host "Built $output"
} finally {
    $env:GOOS, $env:GOARCH = $previousGOOS, $previousGOARCH
    Pop-Location
}
