# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
param(
    [string]$Repo = "."
)

$ErrorActionPreference = "Stop"

# Resolve the target repo relative to the caller's working directory first.
$Repo = (Resolve-Path -Path $Repo).Path

# KeySentry home relative to this script: try script dir ../.. first, then fall
# back to one level up (scripts/ sits directly under the KeySentry root).
$KeySentryHome = (Resolve-Path -Path (Join-Path $PSScriptRoot ".." "..")).Path
if (-not (Test-Path -Path (Join-Path $KeySentryHome "run.py"))) {
    $KeySentryHome = (Resolve-Path -Path (Join-Path $PSScriptRoot "..")).Path
}
if (-not (Test-Path -Path (Join-Path $KeySentryHome "run.py"))) {
    throw "KeySentry run.py not found near $PSScriptRoot"
}

Push-Location $KeySentryHome
try {
    python run.py hooks install --repo $Repo
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}