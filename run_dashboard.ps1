$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
& '.\.venv\Scripts\python.exe' -m streamlit run dashboard.py
if ($LASTEXITCODE -ne 0) { throw 'Dashboard exited with an error.' }
