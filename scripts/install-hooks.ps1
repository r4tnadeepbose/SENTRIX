# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
param(
    [string]$Repo = "."
)

$ErrorActionPreference = "Stop"

# Resolve the target repo relative to the caller's working directory first.
$Repo = (Resolve-Path -Path $Repo).Path

# SENTRIX home relative to this script: try script dir ../.. first, then fall
# back to one level up (scripts/ sits directly under the SENTRIX root).
$SENTRIXHome = (Resolve-Path -Path (Join-Path $PSScriptRoot ".." "..")).Path
if (-not (Test-Path -Path (Join-Path $SENTRIXHome "run.py"))) {
    $SENTRIXHome = (Resolve-Path -Path (Join-Path $PSScriptRoot "..")).Path
}
if (-not (Test-Path -Path (Join-Path $SENTRIXHome "run.py"))) {
    throw "SENTRIX run.py not found near $PSScriptRoot"
}

Push-Location $SENTRIXHome
try {
    python run.py hooks install --repo $Repo
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}