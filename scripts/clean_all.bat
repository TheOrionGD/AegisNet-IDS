@echo off
REM AegisNet SIEM - Complete Localhost Cleanup (Windows Batch)
REM Kills all processes on SIEM-related ports.

echo === AEGISNET SIEM — LOCALHOST CLEANUP ===
echo Target ports: 2345, 2346, 2347, 8000, 1234, 3456, 6379, 9200, 27017
echo.

for %%P in (2345 2346 2347 8000 1234 3456 6379 9200 27017) do (
    echo Checking port %%P...
    REM Find PID using the port
    for /f "tokens=5" %%A in ('netstat -ano ^| findstr :%%P ^| findstr LISTENING') do (
        echo   Killing PID %%A (listening on %%P)
        taskkill /F /PID %%A >nul 2>&1
    )
)

echo.
echo === VERIFICATION ===
for %%P in (2345 2346 2347 8000 1234 3456 6379 9200 27017) do (
    netstat -ano ^| findstr :%%P >nul
    if errorlevel 1 (
        echo [OK]   Port %%P - free
    ) else (
        echo [WARN] Port %%P - still in use!
    )
)

echo.
echo All SIEM-related ports cleared. Run: python run_system.py
pause
