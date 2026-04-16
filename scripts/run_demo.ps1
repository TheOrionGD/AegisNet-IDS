#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Complete CNS ML Pipeline Demo - Windows PowerShell Version
    
.DESCRIPTION
    This script runs the complete anomaly detection pipeline including:
    1. Generating sample Snort alerts
    2. Loading and parsing alerts
    3. Extracting ML features
    4. Training Isolation Forest model
    5. Detecting anomalies
    6. Generating candidate Snort rules from anomalies
    
.PARAMETER SkipInstall
    Skip pip package installation if already installed
    
.EXAMPLE
    .\run_demo.ps1
    .\run_demo.ps1 -SkipInstall
#>

param(
    [switch]$SkipInstall = $false
)

$ErrorActionPreference = "Stop"

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "[*]" -ForegroundColor Yellow -NoNewline
    Write-Host " $Text"
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK]" -ForegroundColor Green -NoNewline
    Write-Host " $Text"
}

function Write-Error2 {
    param([string]$Text)
    Write-Host "[ERROR]" -ForegroundColor Red -NoNewline
    Write-Host " $Text"
}

# Start
Write-Header "CNS IDS + ML Pipeline Demo (Windows)"

# Activate virtual environment
Write-Step "Activating Python virtual environment..."
try {
    & .\.venv\Scripts\Activate.ps1 -ErrorAction Stop 2>&1 | Out-Null
    Write-Success "Virtual environment activated"
} catch {
    Write-Error2 "Failed to activate virtual environment"
    Write-Host "Creating new virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
    & .\.venv\Scripts\Activate.ps1
    Write-Success "New virtual environment created and activated"
}

# Install dependencies
if (-not $SkipInstall) {
    Write-Step "Installing Python packages..."
    pip install -r requirements.txt --quiet --disable-pip-version-check 2>&1 | Where-Object { $_ -match "error|ERROR" }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error2 "Failed to install packages"
        exit 1
    }
    Write-Success "Python packages installed"
} else {
    Write-Step "Skipping package installation (--SkipInstall)"
}

Write-Host ""
Write-Header "Running ML Pipeline Demo"

# Run demo
Write-Step "Executing demo.py..."
python src\demo.py

if ($LASTEXITCODE -ne 0) {
    Write-Error2 "Demo execution failed"
    exit 1
}

Write-Host ""
Write-Header "✓ Demo Completed Successfully!"

Write-Host ""
Write-Host "Output Files Generated:" -ForegroundColor Cyan
Write-Host ""

# Check what was generated
$outputs = @{
    "Sample Data" = "demo_data\alerts.json"
    "Engineered Features" = "demo_output\processed.csv"
    "Trained Model" = "demo_output\model.joblib"
    "Scaler (Normalization)" = "demo_output\scaler.joblib"
    "Detection Results" = "demo_output\results.json"
    "Generated Rules" = "demo_output\generated_rules.rules"
    "Rule Metadata" = "demo_output\generated_rules_metadata.json"
}

foreach ($desc in $outputs.Keys) {
    $file = $outputs[$desc]
    if (Test-Path $file) {
        Write-Host "  ✓ " -ForegroundColor Green -NoNewline
        Write-Host "$desc" -NoNewline
        Write-Host " → " -NoNewline
        Write-Host $file -ForegroundColor White
        
        # Show file size
        $size = (Get-Item $file).Length
        if ($size -gt 1MB) {
            Write-Host "    Size: $([math]::Round($size/1MB, 2)) MB" -ForegroundColor Gray
        } elseif ($size -gt 1KB) {
            Write-Host "    Size: $([math]::Round($size/1KB, 2)) KB" -ForegroundColor Gray
        } else {
            Write-Host "    Size: $size bytes" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Review the detection results:"
Write-Host "   Get-Content demo_output\results.json | ConvertFrom-Json | Format-List"
Write-Host ""
Write-Host "2. Examine detected anomalies:"
Write-Host "   Get-Content demo_output\generated_rules_metadata.json | ConvertFrom-Json"
Write-Host ""
Write-Host "3. View generated Snort rules:"
Write-Host "   Get-Content demo_output\generated_rules.rules"
Write-Host ""
Write-Host "4. For real Snort integration on Linux/WSL:"
Write-Host "   bash install_snort.sh"
Write-Host ""
Write-Host "Project Structure:" -ForegroundColor Cyan
Write-Host "  src/                 → Python source modules"
Write-Host "  config/              → Configuration files (config.yaml)"
Write-Host "  demo_data/           → Generated sample alerts"
Write-Host "  demo_output/         → ML pipeline outputs"
Write-Host "  local.rules          → Snort custom rules"
Write-Host "  snort.lua            → Snort 3 configuration"
Write-Host ""

Write-Host "Documentation:" -ForegroundColor Cyan
Write-Host "  - README.md          → Project overview"
Write-Host "  - config/config.yaml → ML pipeline configuration"
Write-Host ""

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "Demo complete! Check the above files." -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

