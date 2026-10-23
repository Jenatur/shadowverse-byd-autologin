# svs-autologin uninstaller (phase 5 T7). Elevated; mirrors install.ps1.
#
#   powershell -ExecutionPolicy Bypass -File tools\uninstall.ps1              # keep data
#   powershell -ExecutionPolicy Bypass -File tools\uninstall.ps1 -RemoveData  # wipe data dir too
#
# Order: stop proxy (pidfile) -> hosts -> CA -> shortcut -> marker. Data dir
# (config/accounts/logs) kept unless -RemoveData: re-install must not cost
# the user their scanned accounts.

param([switch]$RemoveData)

$ErrorActionPreference = "Stop"
Write-Host "== svs-autologin uninstaller =="

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$marker = Join-Path $Root ".installed"

# ---- data dir (marker) ------------------------------------------------------
$dataDir = $null
if (Test-Path $marker) {
    $dataDir = (Get-Content $marker -First 1).Trim()
} elseif (Test-Path "C:\ProgramData\svs-autologin") {
    $dataDir = "C:\ProgramData\svs-autologin"
}

# ---- 1. stop proxy by pidfile ------------------------------------------------
if ($dataDir) {
    $pidFile = Join-Path $dataDir "proxy.pid"
    if (Test-Path $pidFile) {
        $proxyPid = (Get-Content $pidFile -First 1).Trim()
        if ($proxyPid -match '^\d+$') {
            taskkill /PID $proxyPid /T /F 2>$null | Out-Null
            Write-Host "proxy stopped (pid $proxyPid)"
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
}

# ---- 2. hosts entry ----------------------------------------------------------
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$needle = "service.mkey.163.com"
if (Test-Path $hostsPath) {
    $lines = Get-Content $hostsPath
    $kept = $lines | Where-Object { $_ -notmatch [regex]::Escape($needle) }
    if ($kept.Count -ne $lines.Count) {
        # UTF8, not ascii: hosts may carry non-ASCII entries (other tools,
        # international hostnames) - ascii would corrupt them to '?'.
        Set-Content -Path $hostsPath -Value $kept -Encoding UTF8
        ipconfig /flushdns | Out-Null
        Write-Host "hosts entry removed + dns flushed"
    }
}

# ---- 3. mitmproxy CA ----------------------------------------------------------
# Precise first: if the installed CA file still exists, remove exactly its
# thumbprint. Subject-wide removal is the fallback when the data dir is gone
# (it can hit an unrelated user-owned mitmproxy CA - printed per thumbprint
# so the operator sees exactly what went).
$certsDir = if ($dataDir) { Join-Path $dataDir "certs" } else { $null }
$caCer = if ($certsDir) { Join-Path $certsDir "mitmproxy-ca-cert.cer" } else { $null }
if ($caCer -and (Test-Path $caCer)) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caCer)
    $tp = $cert.Thumbprint
    if (Get-ChildItem ("Cert:\LocalMachine\Root\" + $tp) -ErrorAction SilentlyContinue) {
        Remove-Item -Path ("Cert:\LocalMachine\Root\" + $tp) -Force
        Write-Host "CA removed from Root (exact thumbprint): $tp"
    } else {
        Write-Host "installed CA not in Root store: $tp"
    }
} else {
    $cas = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like "*mitmproxy*" }
    if ($cas) {
        foreach ($ca in $cas) {
            Remove-Item -Path ("Cert:\LocalMachine\Root\" + $ca.Thumbprint) -Force
            Write-Host "CA removed from Root (Subject fallback): $($ca.Thumbprint)"
        }
    } else {
        Write-Host "no mitmproxy CA in Root store"
    }
}

# ---- 4. shortcut -------------------------------------------------------------
$lnk = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\svs-autologin.lnk"
if (Test-Path $lnk) {
    Remove-Item $lnk -Force
    Write-Host "shortcut removed"
}

# ---- 5. marker ---------------------------------------------------------------
if (Test-Path $marker) {
    Remove-Item $marker -Force
    Write-Host "installed marker removed"
}

# ---- 6. data dir (optional) --------------------------------------------------
if ($RemoveData -and $dataDir -and (Test-Path $dataDir)) {
    Remove-Item $dataDir -Recurse -Force
    Write-Host "data dir removed: $dataDir"
} elseif ($dataDir) {
    Write-Host "data dir KEPT (accounts/config/logs): $dataDir"
    Write-Host "  re-run with -RemoveData to delete it too"
}

Write-Host ""
Write-Host "uninstall OK"
