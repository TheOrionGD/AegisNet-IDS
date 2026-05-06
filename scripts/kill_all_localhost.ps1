# AegisNet SIEM — Kill ALL Localhost Processes
# WARNING: This terminates EVERY process listening on 127.0.0.1
# Use with caution. Recommended only for clean dev environment resets.

$allConnections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq '127.0.0.1' -or $_.LocalAddress -eq '::1' }

if (-not $allConnections) {
    Write-Host "No processes listening on localhost (127.0.0.1 / ::1)." -ForegroundColor Green
    exit 0
}

Write-Host "=== KILLING ALL LOCALHOST LISTENERS ===" -ForegroundColor Red
Write-Host "Found $($allConnections.Count) processes on localhost."
Write-Host ""

foreach ($conn in $allConnections) {
    $pid = $conn.OwningProcess
    $addr = $conn.LocalAddress
    $port = $conn.LocalPort
    try {
        $proc = Get-Process -Id $pid -ErrorAction Stop
        $name = $proc.ProcessName
        Write-Host "[KILL] PID $pid ($name) — $addr:$port" -ForegroundColor Yellow
        Stop-Process -Id $pid -Force -ErrorAction Stop
    } catch {
        Write-Host "[KILL] PID $pid (unidentified) — $addr:$port — already dead or no access" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "=== VERIFICATION ===" -ForegroundColor Cyan
$remaining = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq '127.0.0.1' -or $_.LocalAddress -eq '::1' }

if ($remaining) {
    Write-Host "[WARN] $($remaining.Count) processes still on localhost:" -ForegroundColor Red
    $remaining | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize
} else {
    Write-Host "[OK] All localhost ports are now free." -ForegroundColor Green
}

Write-Host ""
Write-Host "All localhost processes terminated." -ForegroundColor Cyan
