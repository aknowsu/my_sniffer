# Checks for the Npcap driver, builds my_sniffer (Release), and reminds the
# user capture needs an Administrator terminal. See README.md for the
# equivalent manual steps.
$ErrorActionPreference = "Stop"

$buildDir = if ($args.Count -ge 1) { $args[0] } else { "build" }

$npcapInstalled = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if (-not $npcapInstalled) {
    Write-Host "Npcap driver not found." -ForegroundColor Yellow
    Write-Host "Install it from https://npcap.com/#download, then re-run this script."
    exit 1
}
Write-Host "Npcap driver found."

cmake -S . -B $buildDir -G "Visual Studio 17 2022"
cmake --build $buildDir --config Release

Write-Host "Build complete: $buildDir\Release\my_sniffer.exe"
Write-Host "Run it from an Administrator terminal -- capture needs elevation."
