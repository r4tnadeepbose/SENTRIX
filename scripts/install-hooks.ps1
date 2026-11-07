# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
param(
    [string]$Repo = "."
)

$ErrorActionPreference = "Stop"

# Resolve the target repo relative to the caller's working directory first.
$Repo = (Resolve-Path -Path $Repo).Path

# Wintermute home relative to this script: try script dir ../.. first, then fall
# back to one level up (scripts/ sits directly under the Wintermute root).
$WintermuteHome = (Resolve-Path -Path (Join-Path $PSScriptRoot ".." "..")).Path
if (-not (Test-Path -Path (Join-Path $WintermuteHome "run.py"))) {
    $WintermuteHome = (Resolve-Path -Path (Join-Path $PSScriptRoot "..")).Path
}
if (-not (Test-Path -Path (Join-Path $WintermuteHome "run.py"))) {
    throw "Wintermute run.py not found near $PSScriptRoot"
}

Push-Location $WintermuteHome
try {
    python run.py hooks install --repo $Repo
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}