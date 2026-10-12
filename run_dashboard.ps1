$ErrorActionPreference = "Stop"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python was not found on PATH."
    exit 1
}

python -m pip install -r requirements.txt
python -m streamlit run dashboard.py
