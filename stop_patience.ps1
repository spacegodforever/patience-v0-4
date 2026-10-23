$ErrorActionPreference = 'Stop'
$pidFile = Join-Path $PSScriptRoot 'runtime\processes.json'
if (-not (Test-Path -LiteralPath $pidFile)) { Write-Host 'No recorded processes.'; return }
foreach ($entry in (Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json)) {
    $process = Get-Process -Id $entry.id -ErrorAction SilentlyContinue
    if ($process -and [string]$process.StartTime.ToUniversalTime().Ticks -eq [string]$entry.startedTicks) { & taskkill.exe /PID $entry.id /T /F | Out-Null; if ($LASTEXITCODE -ne 0) { throw "Failed to stop process tree $($entry.id)." } }
}
Remove-Item -LiteralPath $pidFile
Write-Host 'Recorded PATIENCE processes stopped.'
