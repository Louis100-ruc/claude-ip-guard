$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$Version = "2.3.1"
$DistDir = Join-Path $RootDir "dist"
$OutExe = Join-Path $DistDir "ClaudeIPGuard-v$Version-Windows-x64.exe"

Write-Host "Building ClaudeIPGuard v$Version for Windows (net48 single-file EXE)..."
dotnet build (Join-Path $ScriptDir "ClaudeIPGuard.csproj") -c Release

$BuiltExe = Join-Path $ScriptDir "bin\Release\net48\ClaudeIPGuard.exe"
if (-not (Test-Path $BuiltExe)) {
    throw "Expected output executable not found at $BuiltExe"
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
Copy-Item -Force $BuiltExe $OutExe

Write-Host "Windows EXE ready: $OutExe"
Get-Item $OutExe | Select-Object Name, Length
