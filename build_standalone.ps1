<#
    build_standalone.ps1  --  Build the portable, antivirus-friendly EventHawk standalone.

    Produces (in -OutDir, default .\dist), <version> = evtx_tool.__version__:
      * EventHawk-<version>-Setup.exe     -- Inno Setup installer. Installs for the
        current user (no admin) or for all users, with Start Menu + Desktop shortcuts.
      * EventHawk-<version>-portable.zip  -- extract anywhere, run EventHawk.exe
        (or EventHawk.cmd). Nothing is installed.
    Bundles Python + PySide6 + DuckDB + PyArrow + every dependency and data file.
    End users need NOTHING installed.

    CLEAN-ROOM: this script never reads your local/global Python. It downloads a
    fresh Python "embeddable" build from python.org, HARD-FAILS unless python.exe
    is Authenticode-signed by the Python Software Foundation, unpacks a pinned
    pip wheel checked by SHA-256, and installs requirements-lock.txt with
    --require-hashes --only-binary=:all: -- the exact packages, checked by hash,
    that the test suite runs on -- into an isolated runtime (PYTHONNOUSERSITE=1).

    The Python version is the one the suite runs on (3.12): the default used to
    be 3.14, which nothing had been tested on.

    WHY NOT PyInstaller for the app: its bootloader is an antivirus false-positive
    magnet. The installer's shortcuts start the PSF-signed pythonw.exe. The
    portable folder also carries EventHawk.exe (-Launcher: the small launcher
    built from launcher.py), which starts that same bundled pythonw.exe.

    NOTE ON AGGRESSIVE AV (e.g. Kaspersky): some engines quarantine the Rust EVTX
    parser (evtx/_native.pyd) on fresh install. If that happens, whitelist the
    build folder ($WorkDir) and the install folder in your AV. This is a
    false positive on a legitimate open-source parser.

    Requirements: internet access; Inno Setup 6 for the installer
      (winget install JRSoftware.InnoSetup), or -SkipInstaller.
    Usage:   powershell -ExecutionPolicy Bypass -File build_standalone.ps1 [-Launcher dist\EventHawk.exe]
#>
param(
    [string]$PyVersion = "3.12.10",
    [string]$WorkDir   = "$env:LOCALAPPDATA\eh-build",   # short path (avoids MAX_PATH)
    [string]$OutDir    = "$PSScriptRoot\dist",
    [string]$ISCC      = "",                             # optional explicit ISCC.exe path
    [string]$Launcher  = "",                             # optional EventHawk.exe (launcher.py, PyInstaller)
    [switch]$SkipInstaller
)
$ErrorActionPreference = "Stop"
$env:PYTHONNOUSERSITE = "1"; $env:PYTHONPATH = ""       # isolate from local packages
$repo = $PSScriptRoot
$tag  = ($PyVersion -split '\.')[0..1] -join ''          # 3.12.10 -> 312
$dst  = Join-Path $WorkDir "EventHawk"
# One version for every file name and the installer: the package's own.
$ver = (Select-String -Path "$repo\evtx_tool\__init__.py" -Pattern '^__version__\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
if ($ver -notmatch '^[0-9A-Za-z.+-]+$') { throw "unexpected version in evtx_tool/__init__.py: $ver" }
Write-Host "==> EventHawk $ver, Python $PyVersion"

if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dst, $OutDir | Out-Null

# 1 ── fresh, signature-verified Python -------------------------------------
Write-Host "==> [1/6] Fetching signed embeddable Python $PyVersion from python.org"
$zip = Join-Path $WorkDir "py-embed.zip"
Invoke-WebRequest "https://www.python.org/ftp/python/$PyVersion/python-$PyVersion-embed-amd64.zip" -OutFile $zip
Expand-Archive $zip -DestinationPath $dst -Force
$sig = Get-AuthenticodeSignature "$dst\python.exe"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
    throw "Downloaded python.exe is NOT validly PSF-signed - aborting clean-room build"
}
Write-Host "    verified: $($sig.Status)  [$($sig.SignerCertificate.Subject.Split(',')[0])]"

# 2 ── pip + all dependencies, pinned and hash-checked, isolated -----------
Write-Host "==> [2/6] Bootstrapping pip and installing requirements-lock.txt (isolated from local packages)"
"python$tag.zip`n.`nLib\site-packages`nimport site" | Set-Content "$dst\python$tag._pth" -Encoding ascii
# One pinned pip wheel, refused unless its SHA-256 matches; it was a
# get-pip.py run without any check (Gemini audit 13-04).  A wheel is a zip:
# unpacking it into site-packages installs pip.  To update: take the version,
# URL and sha256 of the new py3-none-any wheel from https://pypi.org/pypi/pip/json
$pipWhl = "pip-26.3-py3-none-any.whl"
$pipUrl = "https://files.pythonhosted.org/packages/07/25/ee8c38ae72d66b844ce8eb9711ba905dba21ca1a8a0c960057c41cd23337/$pipWhl"
$pipSha = 'f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13'
Invoke-WebRequest $pipUrl -OutFile "$WorkDir\$pipWhl"
$pipHash = (Get-FileHash "$WorkDir\$pipWhl" -Algorithm SHA256).Hash.ToLower()
if ($pipHash -ne $pipSha) {
    throw "Downloaded $pipWhl has SHA-256 $pipHash, expected $pipSha - aborting clean-room build"
}
Copy-Item "$WorkDir\$pipWhl" "$WorkDir\pip-wheel.zip"
Expand-Archive "$WorkDir\pip-wheel.zip" -DestinationPath "$dst\Lib\site-packages" -Force
& "$dst\python.exe" -m pip --version
if ($LASTEXITCODE -ne 0) { throw "pip from $pipWhl does not run in the embedded Python" }
# The exact, hash-checked packages the suite runs on.  requirements.txt holds
# only minimum versions: building from it shipped whatever PyPI had that day.
& "$dst\python.exe" -m pip install --no-warn-script-location -q --no-cache-dir `
    --require-hashes --only-binary=:all: -r "$repo\requirements-lock.txt"
if ($LASTEXITCODE -ne 0) { throw "pip install -r requirements-lock.txt failed (exit $LASTEXITCODE)" }

# 3 ── app code + icon + launcher -------------------------------------------
Write-Host "==> [3/6] App code + icon + launcher"
Copy-Item "$repo\evtx_tool" "$dst\evtx_tool" -Recurse -Force
# Sentinel (Tools > Baseline Analysis) is a separate root package; without it
# the installed app reported "Sentinel Not Installed".
Copy-Item "$repo\sentinel" "$dst\sentinel" -Recurse -Force
Copy-Item "$repo\eventhawk_gui.py", "$repo\evtx_tool.py" $dst -Force
Copy-Item "$repo\LICENSE" "$dst\LICENSE.txt" -Force
Copy-Item "$repo\evtx_tool\resources\images\eventhawk_logo.ico" "$dst\EventHawk.ico" -Force
"@echo off`r`nstart """" ""%~dp0pythonw.exe"" ""%~dp0eventhawk_gui.py"" %*" | Set-Content "$dst\EventHawk.cmd" -Encoding ascii
if ($Launcher) {
    if (-not (Test-Path $Launcher)) { throw "launcher not found: $Launcher" }
    Copy-Item $Launcher "$dst\EventHawk.exe" -Force
}

# 4 ── trim dead weight (keep every FEATURE + every dist-info) --------------
Write-Host "==> [4/6] Trimming dead weight"
$sp = "$dst\Lib\site-packages"
'pip', 'setuptools', 'wheel', 'pkg_resources', '_distutils_hack' | ForEach-Object {
    Remove-Item "$sp\$_" -Recurse -Force -ErrorAction SilentlyContinue }
# dist-info: keep them (duckdb etc. read their own metadata) EXCEPT build-only tools
Get-ChildItem $sp -Directory | Where-Object { $_.Name -match '^(pip|setuptools|wheel)-.*\.dist-info$' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $dst -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $sp -Recurse -Filter '*.pyi' | Remove-Item -Force -ErrorAction SilentlyContinue
# PySide6: keep only QtCore/Gui/Widgets/Svg; drop WebEngine/QML/etc.
$ps6 = "$sp\PySide6"
$keepDll = 'Qt6Core','Qt6Gui','Qt6Widgets','Qt6Svg','Qt6SvgWidgets'
$keepPyd = 'QtCore','QtGui','QtWidgets','QtSvg','QtSvgWidgets'
Get-ChildItem $ps6 -Filter 'Qt6*.dll' | Where-Object { $keepDll -notcontains $_.BaseName } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem $ps6 -Filter 'Qt*.pyd'  | Where-Object { $keepPyd -notcontains $_.BaseName } | Remove-Item -Force -ErrorAction SilentlyContinue
'translations','qml','metatypes','typesystems','glue','include','examples','doc','qtasyncio' | ForEach-Object {
    Remove-Item "$ps6\$_" -Recurse -Force -ErrorAction SilentlyContinue }
'opengl32sw.dll','pyside6qml.abi3.dll' | ForEach-Object { Remove-Item "$ps6\$_" -Force -ErrorAction SilentlyContinue }
Get-ChildItem $ps6 -Filter 'av*.dll' | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem $ps6 -Filter 'sw*.dll' | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem $ps6 -Filter '*.exe'   | Remove-Item -Force -ErrorAction SilentlyContinue
if (Test-Path "$ps6\resources") { Get-ChildItem "$ps6\resources" -File | Where-Object Name -ne 'icudtl.dat' | Remove-Item -Force -ErrorAction SilentlyContinue }
'multimedia','sqldrivers','position','sensors','webview','designer','qmltooling','assetimporters',
  'geometryloaders','sceneparsers','renderers','renderplugins','help','texttospeech','tls','networkinformation' |
    ForEach-Object { Remove-Item "$ps6\plugins\$_" -Recurse -Force -ErrorAction SilentlyContinue }
'arrow_flight.dll','arrow_substrait.dll','arrow_python_flight.dll','gandiva.dll' | ForEach-Object {
    Remove-Item "$sp\pyarrow\$_" -Force -ErrorAction SilentlyContinue }

# Final ._pth: isolated (no `import site`) so the DEPLOYED app never reads the
# end user's global packages either.
"python$tag.zip`n.`nLib\site-packages" | Set-Content "$dst\python$tag._pth" -Encoding ascii
$mb = [math]::Round((Get-ChildItem $dst -Recurse | Measure-Object Length -Sum).Sum / 1MB)
Write-Host "    runtime: $mb MB"

# 5 ── portable ZIP (extract-and-run, no install) ---------------------------
Write-Host "==> [5/6] Building the portable ZIP"
$portable = Join-Path $OutDir "EventHawk-$ver-portable.zip"
if (Test-Path $portable) { Remove-Item $portable -Force }
$sevenZip = @("$env:ProgramFiles\7-Zip\7z.exe","${env:ProgramFiles(x86)}\7-Zip\7z.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($sevenZip) {
    # The folder itself goes in, so the ZIP extracts to one EventHawk folder.
    & $sevenZip a -tzip -mx=7 "$portable" "$dst" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7-Zip failed (exit $LASTEXITCODE)" }
} else {
    Compress-Archive -Path $dst -DestinationPath $portable -CompressionLevel Optimal
}
Write-Host "    portable: $portable ($([math]::Round((Get-Item $portable).Length/1MB)) MB)"

# 6 ── Inno Setup installer -------------------------------------------------
if ($SkipInstaller) {
    Write-Host "==> [6/6] Installer skipped (-SkipInstaller)"
} else {
    Write-Host "==> [6/6] Building installer with Inno Setup"
    if (-not $ISCC) {
        $ISCC = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe","$env:ProgramFiles\Inno Setup 6\ISCC.exe",
                  "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
            Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $ISCC) { throw "Inno Setup not found. Install with: winget install JRSoftware.InnoSetup  (or pass -ISCC <path>, or -SkipInstaller)" }
    & $ISCC "/DSourceDir=$dst" "/DMyAppVersion=$ver" "/O$OutDir" "$repo\EventHawk.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compile failed (exit $LASTEXITCODE)" }
}

Write-Host "`nDONE:" -ForegroundColor Green
$setup = Join-Path $OutDir "EventHawk-$ver-Setup.exe"
if (Test-Path $setup) { Write-Host "  installer: $setup ($([math]::Round((Get-Item $setup).Length/1MB)) MB)" -ForegroundColor Green }
Write-Host "  portable : $portable" -ForegroundColor Green
Write-Host "  runtime  : $dst" -ForegroundColor Green
