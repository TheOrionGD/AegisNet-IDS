@echo off
REM Windows Batch Script - Complete CNS ML Pipeline Demo
REM This script sets up the Python environment and runs the full anomaly detection pipeline

setlocal enabledelayedexpansion

color 3F
title CNS IDS + ML Pipeline Demo

echo.
echo ============================================
echo CNS IDS + ML Pipeline Demo (Windows Batch)
echo ============================================
echo.

REM Activate virtual environment
echo Activating Python environment...
call .venv\Scripts\activate.bat

if errorlevel 1 (
    echo Creating new virtual environment...
    python -m venv .venv
    call .venv\Scripts\activate.bat
)

REM Install dependencies
echo Installing Python packages...
pip install -r requirements.txt --quiet --disable-pip-version-check

if errorlevel 1 (
    color 4F
    echo.
    echo ============================================
    echo ERROR: Failed to install packages
    echo ============================================
    exit /b 1
)

echo.
echo ============================================
echo Running ML Pipeline Demo
echo ============================================
echo.

REM Run the demo
python src\demo.py

if errorlevel 1 (
    color 4F
    echo.
    echo ============================================
    echo ERROR: Demo failed
    echo ============================================
    exit /b 1
)

color 2F
echo.
echo ============================================
echo Demo completed successfully!
echo ============================================
echo.
echo Generated Output Files:
echo.
if exist demo_data\alerts.json (
    echo   [OK] demo_data\alerts.json
    echo        Sample network traffic data
)
if exist demo_output\processed.csv (
    echo   [OK] demo_output\processed.csv
    echo        Engineered ML features
)
if exist demo_output\model.joblib (
    echo   [OK] demo_output\model.joblib
    echo        Trained Isolation Forest model
)
if exist demo_output\scaler.joblib (
    echo   [OK] demo_output\scaler.joblib
    echo        Feature normalization scaler
)
if exist demo_output\results.json (
    echo   [OK] demo_output\results.json
    echo        Anomaly detection results
)
if exist demo_output\generated_rules.rules (
    echo   [OK] demo_output\generated_rules.rules
    echo        Generated Snort rules from anomalies
)
if exist demo_output\generated_rules_metadata.json (
    echo   [OK] demo_output\generated_rules_metadata.json
    echo        Rule generation metadata
)
echo.
echo Next Steps:
echo   1. Review the results:
echo      type demo_output\results.json
echo.
echo   2. Review generated Snort rules:
echo      type demo_output\generated_rules.rules
echo.
echo   3. For real Snort integration on Linux/WSL:
echo      bash install_snort.sh
echo.
echo Project Files:
echo   - src\              Python source modules
echo   - config\           Configuration (config.yaml)
echo   - demo_data\        Sample data generated
echo   - demo_output\      Pipeline outputs
echo   - local.rules       Snort custom rules
echo   - snort.lua         Snort 3 configuration
echo.

pause
