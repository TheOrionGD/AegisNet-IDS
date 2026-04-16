# CNS IDS: Snort 3 Windows Runner
# Automatically detects VMware interfaces and starts Snort

$ErrorActionPreference = "Stop"

# 1. Ensure logs directory exists
$LogDir = "logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}

$AlertFile = "$LogDir\alert.json"
if (-not (Test-Path $AlertFile)) {
    New-Item -ItemType File -Path $AlertFile | Out-Null
}

Write-Host "--- CNS IDS: Snort 3 Windows Runner ---" -ForegroundColor Cyan

# 2. List Interfaces and Detect VMware
Write-Host "[*] Searching for VMware network interfaces..." -ForegroundColor Yellow
$Interfaces = & snort --list-interfaces 2>$null

if ($null -eq $Interfaces) {
    Write-Error "Snort 3 is not installed or not in your PATH."
    exit 1
}

# Look for VMware or VMnet in the list
$VMwareInterface = $Interfaces | Where-Object { $_ -match "VMware" -or $_ -match "VMnet" }

if ($null -eq $VMwareInterface) {
    Write-Host "[!] No VMware-specific interfaces detected automatically." -ForegroundColor Red
    Write-Host "Available interfaces:" -ForegroundColor Gray
    $Interfaces | ForEach-Object { Write-Host "  $_" }
    
    $InputInterface = Read-Host "Please enter the Interface Name or Index to monitor (e.g., 1 or \Device\NPF_{...})"
    if ([string]::IsNullOrWhiteSpace($InputInterface)) {
        Write-Error "No interface selected. Exiting."
        exit 1
    }
} else {
    Write-Host "[OK] Detected VMware Interface(s):" -ForegroundColor Green
    $VMwareInterface | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    
    # Try to extract the index (Snort 3 usually prefix with index)
    # Example: 1: \Device\NPF_{...} (VMware Network Adapter VMnet8)
    $FirstMatch = $VMwareInterface[0]
    if ($FirstMatch -match "^(\d+):") {
        $InputInterface = $Matches[1]
        Write-Host "[*] Auto-selecting interface index: $InputInterface" -ForegroundColor Yellow
    } else {
        $InputInterface = Read-Host "Could not auto-detect index. Enter index or name manually"
    }
}

# 3. Running Snort
Write-Host "[*] Starting Snort 3 on interface $InputInterface..." -ForegroundColor Cyan
Write-Host "Using configuration: config\snort\snort.lua" -ForegroundColor Gray

# Use --plugin-path if necessary, but standard install should be fine
# We use -c for config, -i for interface, -l for log dir
& snort -c config\snort\snort.lua -i $InputInterface -l $LogDir
