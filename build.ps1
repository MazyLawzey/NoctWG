# Build NoctWG for Windows
$ErrorActionPreference = "Stop"

$Version = "v0.1.0"
try {
    $Version = git describe --tags --always --dirty 2>$null
} catch {}

$LdFlags = "-ldflags `"-X main.Version=$Version`""

Write-Host "Building NoctWG Server..." -ForegroundColor Green
if (!(Test-Path "bin")) { New-Item -ItemType Directory -Path "bin" | Out-Null }
go build $LdFlags -o bin/noctwg-server.exe ./cmd/noctwg-server

Write-Host "Building NoctWG Client..." -ForegroundColor Green
go build $LdFlags -o bin/noctwg-client.exe ./cmd/noctwg-client

Write-Host "Build complete!" -ForegroundColor Green
Write-Host "Binaries are in the 'bin' folder"
