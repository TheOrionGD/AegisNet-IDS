# Clean zombie processes listening on port 2346
$port = 2346
Write-Host "Checking for processes on port $port..."

$connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if (-not $connections) {
    Write-Host "No processes found listening on port $port."
    exit 0
}

foreach ($conn in $connections) {
    $pid = $conn.OwningProcess
    if ($pid) {
        Write-Host "Killing process PID $pid listening on port $port..."
        Stop-Process -Id $pid -Force
    }
}
Write-Host "Port $port cleaned."
