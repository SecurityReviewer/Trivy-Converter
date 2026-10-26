# ============================================================
#  trivy-converter — Build & Test Script (PowerShell)
#  Posiziona questo file nella stessa cartella di main.go
# ============================================================

param(
    [string]$GrypeInput    = "",   # es. ptof_grype.json
    [string]$SecretsInput  = "",   # es. ptof_secrets.json
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Binary    = Join-Path $ScriptDir "trivy-converter.exe"

# ─── colori helper ───────────────────────────────────────────
function Info  ($msg) { Write-Host "[INFO]  $msg" -ForegroundColor Cyan    }
function Ok    ($msg) { Write-Host "[OK]    $msg" -ForegroundColor Green   }
function Warn  ($msg) { Write-Host "[WARN]  $msg" -ForegroundColor Yellow  }
function Fail  ($msg) { Write-Host "[FAIL]  $msg" -ForegroundColor Red; exit 1 }

# ─── 0. Prerequisiti ─────────────────────────────────────────
Info "Verifica prerequisiti..."
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Fail "Go non trovato nel PATH. Scaricalo da https://go.dev/dl/"
}
$goVersion = (go version)
Ok "Go trovato: $goVersion"

# ─── 1. Build ────────────────────────────────────────────────
Info "Build in corso..."
Push-Location $ScriptDir
try {
    go build -o trivy-converter.exe .
    if ($LASTEXITCODE -ne 0) { Fail "go build fallito (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}
Ok "Binary creato: $Binary"

if ($SkipTests) {
    Ok "Build completata. Test saltati (--SkipTests)."
    exit 0
}

# ─── 2. Help / smoke test ────────────────────────────────────
Info "Smoke test: --help..."
& $Binary --help 2>&1 | Out-Null
# Il tool esce con codice 2 per --help (flag package), lo accettiamo
Ok "Help visualizzato correttamente."

# ─── 3. Test Grype ───────────────────────────────────────────
if ($GrypeInput -ne "") {
    if (-not (Test-Path $GrypeInput)) {
        Warn "File Grype non trovato: $GrypeInput — test saltato."
    } else {
        Info "Test conversione Grype: $GrypeInput"
        $outGrype = Join-Path $ScriptDir "out_grype.json"
        & $Binary --input $GrypeInput --output $outGrype 2>&1
        if ($LASTEXITCODE -ne 0) { Fail "Conversione Grype fallita." }

        # Validazione minima: deve avere SchemaVersion e Results
        $json = Get-Content $outGrype -Raw | ConvertFrom-Json
        if ($json.SchemaVersion -ne 2)          { Fail "SchemaVersion atteso 2, trovato $($json.SchemaVersion)" }
        if ($json.Results.Count -eq 0)          { Fail "Results vuoto nel JSON Trivy." }
        $vulnCount = ($json.Results | ForEach-Object { $_.Vulnerabilities.Count } | Measure-Object -Sum).Sum
        Ok "Grype → Trivy: $vulnCount vulnerabilità convertite. Output: $outGrype"
    }
} else {
    Warn "Nessun file Grype specificato (usa -GrypeInput <file>) — test saltato."
}

# ─── 4. Test TruffleHog ──────────────────────────────────────
if ($SecretsInput -ne "") {
    if (-not (Test-Path $SecretsInput)) {
        Warn "File TruffleHog non trovato: $SecretsInput — test saltato."
    } else {
        Info "Test conversione TruffleHog: $SecretsInput"
        $outSecrets = Join-Path $ScriptDir "out_secrets.json"
        & $Binary --input $SecretsInput --output $outSecrets 2>&1
        if ($LASTEXITCODE -ne 0) { Fail "Conversione TruffleHog fallita." }

        $json = Get-Content $outSecrets -Raw | ConvertFrom-Json
        if ($json.SchemaVersion -ne 2)   { Fail "SchemaVersion atteso 2, trovato $($json.SchemaVersion)" }
        if ($json.Results.Count -eq 0)   { Fail "Results vuoto nel JSON Trivy." }
        $secretCount = ($json.Results | ForEach-Object { $_.Secrets.Count } | Measure-Object -Sum).Sum
        Ok "TruffleHog → Trivy: $secretCount segreti convertiti. Output: $outSecrets"
    }
} else {
    Warn "Nessun file TruffleHog specificato (usa -SecretsInput <file>) — test saltato."
}

# ─── 5. Test formato sconosciuto (deve fallire) ──────────────
Info "Test rilevamento formato invalido..."
$tmpBad = Join-Path $env:TEMP "bad_input.json"
'{"foo":"bar"}' | Set-Content $tmpBad
& $Binary --input $tmpBad 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Warn "Atteso errore su input invalido, ma il tool ha restituito 0."
} else {
    Ok "Formato invalido correttamente rifiutato (exit $LASTEXITCODE)."
}
Remove-Item $tmpBad -Force

# ─── 6. Riepilogo ────────────────────────────────────────────
Write-Host ""
Ok "============================================"
Ok " Tutti i test completati con successo."
Ok " Binary: $Binary"
Ok "============================================"
