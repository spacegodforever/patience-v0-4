$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Run setup_patience.ps1 first to create the local Python environment.'
}
$runtimePath = Join-Path $PSScriptRoot 'runtime'
New-Item -ItemType Directory -Path $runtimePath -Force | Out-Null
$pidFile = Join-Path $runtimePath 'processes.json'
if (Test-Path -LiteralPath $pidFile) {
    $previous = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
    foreach ($entry in $previous) {
        $process = Get-Process -Id $entry.id -ErrorAction SilentlyContinue
        if ($process -and [string]$process.StartTime.ToUniversalTime().Ticks -eq [string]$entry.startedTicks) {
            throw 'PATIENCE has recorded running processes. Use stop_patience.ps1 before restarting.'
        }
    }
}
$listener = Get-NetTCPConnection -LocalPort 8504 -State Listen -ErrorAction SilentlyContinue
if ($listener) { throw 'Port 8504 is already in use. Existing listener was preserved.' }
$processes = @()
try {
    foreach ($service in @('dashboard', 'agent')) {
        $arguments = if ($service -eq 'dashboard') { @('-m','streamlit','run','dashboard.py') } else { @('-u','agent_daemon.py') }
        $process = Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtimePath "$service.stdout.log") -RedirectStandardError (Join-Path $runtimePath "$service.stderr.log") -PassThru
        $processes += $process
    }
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        foreach ($process in $processes) {
            $process.Refresh()
            if ($process.HasExited) { throw 'PATIENCE process exited. Inspect runtime stderr logs.' }
        }
        try {
            $response = Invoke-WebRequest 'http://127.0.0.1:8504/_stcore/health' -TimeoutSec 1
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Dashboard health check timed out.' }
    @($processes | ForEach-Object { @{ id = $_.Id; startedTicks = [string]$_.StartTime.ToUniversalTime().Ticks } }) | ConvertTo-Json | Set-Content -LiteralPath $pidFile -Encoding utf8
    Write-Host 'PATIENCE v0.4 is running at http://127.0.0.1:8504'
    Write-Host 'Trigger agent running. Logs: runtime/. Stop: .\stop_patience.ps1'
} catch {
    foreach ($process in $processes) { if (-not $process.HasExited) { & taskkill.exe /PID $process.Id /T /F | Out-Null } }
    throw
}
