# PATIENCE local installer for Windows PowerShell (5+ or PowerShell 7).
# Delegates to tools/install.py (stdlib only) so the steps stay in one tested place.
# If the script is blocked, run: Set-ExecutionPolicy -Scope Process Bypass
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Root) {
    $Root = (Get-Location).Path
}
$InstallPy = Join-Path $Root "tools\install.py"
if (-not (Test-Path -LiteralPath $InstallPy)) {
    Write-Error "PATIENCE installer: $InstallPy is missing. Run this script from a PATIENCE checkout."
    exit 1
}

function Find-InstallerPython {
    if ($env:PYTHON) {
        return $env:PYTHON
    }
    foreach ($name in @("python3", "python")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            return $cmd.Source
        }
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return $py.Source
    }
    return $null
}

$Python = Find-InstallerPython
if (-not $Python) {
    Write-Host "PATIENCE installer: Python 3 was not found on PATH."
    Write-Host "PATIENCE needs Python 3.10 or newer (the exact floor is read from pyproject.toml)."
    Write-Host "Install Python from https://www.python.org/downloads/ and re-run this script."
    exit 1
}

# The Windows `py` launcher needs a version argument when invoked by that name alone.
$pythonArgs = @($InstallPy) + $args
if ((Split-Path -Leaf $Python) -match '^py(\.exe)?$') {
    & $Python -3 @pythonArgs
} else {
    & $Python @pythonArgs
}
exit $LASTEXITCODE
