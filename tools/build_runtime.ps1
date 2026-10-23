# Build the self-contained distribution runtime (phase 5, plan T3).
#
#   powershell -ExecutionPolicy Bypass -File tools\build_runtime.ps1
#
# Produces:
#   dist/runtime/                          python 3.12 embeddable + pinned deps
#   dist/svs-autologin/<version>/          the shippable tree (runtime + code + docs)
#
# All network access happens HERE, at build time, from this developer machine:
# python.org (embeddable zip), bootstrap.pypa.io (get-pip), pypi.org (wheels).
# The shipped artifact itself makes zero outbound connections (C1).
# dist/ is in SKIP_DIRS of tests/_scan.py, so the vendored tree is never scanned.
#
# NOTE: keep console output ASCII-only - codepages on build machines vary.

param([switch]$SkipRuntime)

$ErrorActionPreference = "Stop"

$Root      = Resolve-Path (Join-Path $PSScriptRoot "..")
$Dist      = Join-Path $Root "dist"
$Runtime   = Join-Path $Dist "runtime"
$CacheDir  = Join-Path $Dist "downloads"

$PythonVersion = "3.12.10"
$PythonUrl     = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
$GetPipUrl     = "https://bootstrap.pypa.io/get-pip.py"

# ---- helpers ----------------------------------------------------------------

function Get-File($url, $dest) {
    if (Test-Path $dest) {
        Write-Host "cached: $dest"
        return
    }
    Write-Host "downloading $url"
    # TLS 1.2 for older PowerShell hosts
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}

# ---- 1. python embeddable ---------------------------------------------------

if (-not $SkipRuntime) {
    New-Item -ItemType Directory -Force $Runtime | Out-Null
    New-Item -ItemType Directory -Force $CacheDir | Out-Null

    $pyExe = Join-Path $Runtime "python.exe"
    if (Test-Path $pyExe) {
        Write-Host "runtime python already present, skipping embed setup"
    } else {
        $zip = Join-Path $CacheDir "python-$PythonVersion-embed-amd64.zip"
        Get-File $PythonUrl $zip
        Write-Host "extracting embeddable into $Runtime"
        Expand-Archive -Path $zip -DestinationPath $Runtime -Force

        # The embeddable distro ignores site-packages by default: enable it.
        $pth = Join-Path $Runtime "python312._pth"
        if (-not (Test-Path $pth)) { throw "expected $pth not found after extract" }
        (Get-Content $pth) -replace "^#\s*import site", "import site" | Set-Content -Path $pth -Encoding ascii
        Write-Host "uncommented 'import site' in python312._pth"

        # Bootstrap pip via get-pip (embeddable ships none).
        $getpip = Join-Path $CacheDir "get-pip.py"
        Get-File $GetPipUrl $getpip
        & $pyExe $getpip --no-warn-script-location
        if ($LASTEXITCODE -ne 0) { throw "get-pip failed" }
    }

    # ---- 2. pinned deps -----------------------------------------------------

    # setuptools FIRST, separately: pip 26 builds sdist dependencies in an
    # isolated env that does NOT see already-installed packages, but pyperclip
    # 1.9.0 (pinned by mitmproxy 11.1.3) is sdist-only and its build backend
    # needs setuptools. Installing setuptools into the runtime before the
    # main install makes pip reuse it (pip only isolates what's missing).
    & $pyExe -m pip install --no-warn-script-location setuptools
    if ($LASTEXITCODE -ne 0) { throw "pip install setuptools failed" }

    $LockFile = Join-Path (Join-Path $Root "tools") "requirements.lock"
    & $pyExe -m pip install --no-warn-script-location -r $LockFile
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

    & $pyExe -m pip check
    if ($LASTEXITCODE -ne 0) { throw "pip check failed" }
}

# ---- 3. assemble the shippable tree ------------------------------------------

# Self-heal: a previous run that failed mid-script leaves the runtime inside
# the old ship tree. Move it back so -SkipRuntime rebuilds work.
if (-not (Test-Path $Runtime)) {
    $stray = @()
    foreach ($d in (Get-ChildItem (Join-Path $Dist "svs-autologin") -Directory -ErrorAction SilentlyContinue)) {
        $candidate = Join-Path $d.FullName "runtime"
        if (Test-Path $candidate) { $stray += $candidate }
    }
    if ($stray.Count -gt 0) {
        New-Item -ItemType Directory -Force (Split-Path $Runtime) | Out-Null
        Move-Item $stray[0] $Runtime
        Write-Host "recovered runtime from previous ship tree"
    }
}

$Version = & (Join-Path $Runtime "python.exe") -c "import sys; sys.path.insert(0, r'$Root'); from svs_autologin import __version__; print(__version__)"
if (-not $Version) { throw "could not read svs_autologin.__version__" }

$Ship = Join-Path (Join-Path $Dist "svs-autologin") $Version
if (Test-Path $Ship) { Remove-Item -Recurse -Force $Ship }
New-Item -ItemType Directory -Force $Ship | Out-Null

# runtime moves in whole (python.exe is position-independent once ._pth is set).
Move-Item -Path $Runtime -Destination (Join-Path $Ship "runtime")

foreach ($item in @("svs_autologin", "tools", "docs", "spec", "config.example.json")) {
    Copy-Item -Path (Join-Path $Root $item) -Destination $Ship -Recurse -Force
}

# exe launcher (user request 2026-10-14): csc ships with every Windows
# (.NET Framework 4), so this adds no build-time download (C1).
$Csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $Csc)) { $Csc = $Csc -replace "Framework64", "Framework" }
if (Test-Path $Csc) {
    $LauncherExe = Join-Path $Ship "svs-autologin.exe"
    $LauncherSrc = Join-Path $Root "tools\launcher.cs"
    & $Csc /nologo /target:winexe "/out:$LauncherExe" "$LauncherSrc"
    if ($LASTEXITCODE -ne 0) { throw "launcher compile failed" }
    Write-Host "launcher: $LauncherExe"
} else {
    Write-Host "WARNING: csc.exe not found - shipping without exe launcher" -ForegroundColor Yellow
}

# Privacy pass (2026-10-14 user directive): strip dev-only docs/tools and
# real identifiers from the SHIP COPY ONLY - repo originals stay untouched
# (they are working files). sanitize_ship.py is the single record of every
# replacement; run it on the ship tree after every rebuild.
$ShipPy = Join-Path $Ship "runtime\python.exe"
& $ShipPy (Join-Path $Root "tools\sanitize_ship.py") $Ship
if ($LASTEXITCODE -ne 0) { throw "sanitize pass failed" }

# dev droppings never ship (compiled from the wrong env; target machine
# regenerates what it needs)
foreach ($pycache in (Get-ChildItem $Ship -Recurse -Directory -Filter "__pycache__")) {
    Remove-Item $pycache.FullName -Recurse -Force
}

# Nothing secret ships: config.local.json / accounts.json / *.pem are never
# part of this copy set (explicit include-list, not exclude-list).
Write-Host ""
Write-Host "shippable tree: $Ship"
Get-ChildItem $Ship | Select-Object Name

Write-Host ""
Write-Host "sanity: shipped python -c 'import PySide6, mitmproxy, requests'"
& (Join-Path (Join-Path $Ship "runtime") "python.exe") -c "import PySide6, mitmproxy, requests; print('imports OK')"

# ---- 4. zip artifact ---------------------------------------------------------

$ZipStage = Join-Path $Dist "zipstage"
$ZipRoot = Join-Path $ZipStage "svs-autologin"
if (Test-Path $ZipStage) { Remove-Item $ZipStage -Recurse -Force }
New-Item -ItemType Directory -Force $ZipStage | Out-Null
Copy-Item -Path $Ship -Destination $ZipRoot -Recurse -Force

$Zip = Join-Path $Dist "svs-autologin-$Version.zip"
if (Test-Path $Zip) { Remove-Item $Zip -Force }
Compress-Archive -Path $ZipRoot -DestinationPath $Zip -CompressionLevel Optimal
Remove-Item $ZipStage -Recurse -Force
Write-Host ""
Write-Host "zip: $Zip"
Get-FileHash $Zip -Algorithm SHA256 | Format-List Algorithm, Hash, Path
