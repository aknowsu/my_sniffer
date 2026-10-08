# Installs build dependencies if missing (CMake, Npcap), builds my_sniffer
# (Release), and reminds the user capture needs an Administrator terminal.
# See README.md for the equivalent manual steps.
$ErrorActionPreference = "Stop"

$buildDir = if ($args.Count -ge 1) { $args[0] } else { "build" }

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Write-Host "CMake not found." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Installing CMake via winget..."
        winget install -e --id Kitware.CMake
        Write-Host "Open a new terminal (PATH needs to refresh), then re-run this script."
    } else {
        Write-Host "Install it from https://cmake.org/download/, then re-run this script."
    }
    exit 1
}

$npcapInstalled = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if (-not $npcapInstalled) {
    Write-Host "Npcap driver not found." -ForegroundColor Yellow
    Write-Host "Install it from https://npcap.com/#download, then re-run this script."
    exit 1
}
Write-Host "Npcap driver found."

cmake -S . -B $buildDir -G "Visual Studio 17 2022"
if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake generation failed -- is Visual Studio 2022 (with the C++ workload) installed?" -ForegroundColor Yellow
    Write-Host "Get it from https://visualstudio.microsoft.com/downloads/"
    exit 1
}
cmake --build $buildDir --config Release

Write-Host "Build complete: $buildDir\Release\my_sniffer.exe"
Write-Host "Run it from an Administrator terminal -- capture needs elevation."
