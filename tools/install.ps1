# svs-autologin installer (phase 5 T7). Idempotent; run from an elevated shell
# (setup.bat does that for the user).
#
# System changes it makes (the ONLY ones, by design):
#   1. C:\ProgramData\svs-autologin\  data dir + ACL (Users modify)
#   2. <data>\certs\                  mitmproxy CA generated (gen_ca.py)
#   3. Cert:\LocalMachine\Root        CA imported (game TLS trust)
#   4. hosts entry                    127.0.0.1 service.mkey.163.com
#   5. <install root>\.installed      marker file (data dir absolute path)
#   6. Start Menu shortcut            runtime pythonw + gui_app.py
#
# Console output is ASCII on purpose (risk list #8: console codepage).

param(
    [string]$DataDir = "C:\ProgramData\svs-autologin",
    [switch]$SkipShortcut
)

$ErrorActionPreference = "Stop"
# ASCII-safe banner (console codepage roulette on other machines)
Write-Host "== svs-autologin installer =="

# .Path: Resolve-Path yields a PathInfo object; COM property assignment
# (shortcut.WorkingDirectory) rejects it. Everything else tolerates both,
# so normalize once here.
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# ---- 1. data dir + ACL -----------------------------------------------------
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Write-Host "created data dir: $DataDir"
}
# Users get Modify on the data dir (config/accounts/logs are written by the
# GUI at runtime, which runs unelevated). OI/CI so children inherit.
$acl = Get-Acl $DataDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule)
Set-Acl -Path $DataDir -AclObject $acl
Write-Host "ACL: Users=Modify on $DataDir"

# certs subdir: the mitm CA private key. Data dir carries Users=Modify
# (config/accounts/logs are runtime-writable), but the CA that LocalMachine\Root
# trusts must NOT be writable by every user - anyone replacing it gets a
# machine-trusted MITM CA. So certs breaks inheritance and gets the precise
# set (spec section 1): SYSTEM/Administrators full, installing user full
# (the proxy signs leaf certs unelevated), Users read-only.
$certsDir = Join-Path $DataDir "certs"
if (-not (Test-Path $certsDir)) {
    New-Item -ItemType Directory -Path $certsDir -Force | Out-Null
}
$certsAcl = Get-Acl $certsDir
$certsAcl.SetAccessRuleProtection($true, $false)  # drop inherited Users=Modify
$inherit = "ContainerInherit,ObjectInherit"
# PS 5.1: positional array splat does NOT hit the 5-arg ctor (it binds as 2
# args). Build each rule with explicit -ArgumentList of 5.
$ruleSids = @("S-1-5-18", "S-1-5-32-544")   # SYSTEM, Administrators
$ruleSids += [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($sid in $ruleSids) {
    $certsAcl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        (New-Object System.Security.Principal.SecurityIdentifier($sid)),
        "FullControl", $inherit, "None", "Allow")))
}
$certsAcl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")),
    "ReadAndExecute", $inherit, "None", "Allow")))
Set-Acl -Path $certsDir -AclObject $certsAcl
Write-Host "ACL: certs = SYSTEM/Admins/user Full, Users Read (private key hardened)"

# ---- 2. CA generation (runtime python, deterministic) ----------------------
$Py = Join-Path $Root "runtime\python.exe"
if (-not (Test-Path $Py)) {
    Write-Host "MISSING runtime python: $Py" -ForegroundColor Red
    Write-Host "This zip should contain runtime\ - did extraction drop it?" -ForegroundColor Red
    exit 1
}

$env:SVS_DATA_DIR = $DataDir
try {
    & $Py (Join-Path $Root "tools\gen_ca.py") $certsDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "CA generation FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }
} finally {
    Remove-Item Env:\SVS_DATA_DIR -ErrorAction SilentlyContinue
}
$caPem = Join-Path $certsDir "mitmproxy-ca-cert.cer"
if (-not (Test-Path $caPem)) {
    Write-Host "MISSING CA file after generation: $caPem" -ForegroundColor Red
    exit 1
}

# ---- 3. import CA into LocalMachine\Root -----------------------------------
# Match by THIS cert's thumbprint, not by Subject: a dev machine may already
# carry a DIFFERENT mitmproxy CA in Root (e.g. the developer's own). The proxy
# signs leaf certs with the CA in certs\, so Root must trust exactly that one;
# "some mitmproxy cert exists" would silently break TLS on first login.
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caPem)
$tp = $cert.Thumbprint
if (Get-ChildItem ("Cert:\LocalMachine\Root\" + $tp) -ErrorAction SilentlyContinue) {
    Write-Host "this CA already in Root store (thumbprint $tp)"
} else {
    Import-Certificate -FilePath $caPem -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host "CA imported into LocalMachine\Root (thumbprint $tp)"
}

# ---- 4. hosts entry ---------------------------------------------------------
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$needle = "service.mkey.163.com"
$hostsHasEntry = Select-String -Path $hostsPath -Pattern ([regex]::Escape($needle)) -Quiet -ErrorAction SilentlyContinue
if (-not $hostsHasEntry) {
    Add-Content -Path $hostsPath -Value "`r`n127.0.0.1 $needle"
    Write-Host "hosts entry added: 127.0.0.1 $needle"
} else {
    Write-Host "hosts entry already present"
}

# ---- 5. .installed marker ---------------------------------------------------
$marker = Join-Path $Root ".installed"
Set-Content -Path $marker -Value $DataDir -Encoding ascii
Write-Host "installed marker: $marker -> $DataDir"

# ---- 6. Start Menu shortcut -------------------------------------------------
if (-not $SkipShortcut) {
    $launcherExe = Join-Path $Root "svs-autologin.exe"
    $shortcutDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    $lnk = Join-Path $shortcutDir "svs-autologin.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($lnk)
    if (Test-Path $launcherExe) {
        $sc.TargetPath = $launcherExe
        $sc.Arguments = ""
    } else {
        $pythonw = Join-Path $Root "runtime\pythonw.exe"
        $sc.TargetPath = $pythonw
        $sc.Arguments = "`"$Root\tools\gui_app.py`""
        $sc.IconLocation = "$pythonw,0"
    }
    $sc.WorkingDirectory = $Root
    $sc.Save()
    Write-Host "shortcut: $lnk"
}

# ---- 7. default config (first install only) ---------------------------------
$configPath = Join-Path $DataDir "config.local.json"
if (-not (Test-Path $configPath)) {
    $example = Join-Path $Root "config.example.json"
    if (Test-Path $example) {
        Copy-Item $example $configPath
        # strip dev-only log_key comments? No - example ships with empty log_key.
        Write-Host "default config created: $configPath (edit games.ma68 / auto as needed)"
    }
}

Write-Host ""
Write-Host "install OK - start menu: svs-autologin"
