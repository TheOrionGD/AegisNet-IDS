# AegisNet SIEM - Complete Localhost Cleanup (Windows PowerShell)
# Kills all processes on SIEM-related ports and common services.

$ports = @(2345, 2346, 2347, 8000, 1234, 3456, 6379, 9200, 27017)

Write-Host "=== AEGISNET SIEM — LOCALHOST CLEANUP ===" -ForegroundColor Cyan
Write-Host "Target ports: $($ports -join ', ')"
Write-Host ""

foreach ($port in $ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($connections) {
        Write-Host "[KILL] Port $port — terminating processes..." -ForegroundColor Yellow
        foreach ($conn in $connections) {
            $pid = $conn.OwningProcess
            if ($pid) {
                Write-Host "  → Killing PID $pid" -ForegroundColor Red
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        Write-Host "[CLEAN] Port $port — already free" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "=== VERIFICATION ===" -ForegroundColor Cyan
foreach ($port in $ports) {
    $stillInUse = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($stillInUse) {
        Write-Host "[WARN] Port $port — still in use!" -ForegroundColor Red
    } else {
        Write-Host "[OK]   Port $port — free" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "All SIEM-related ports cleared. Run: python run_system.py" -ForegroundColor Cyan
