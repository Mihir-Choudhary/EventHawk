<#
    build_standalone.ps1  --  Build the portable, antivirus-friendly EventHawk standalone.

    Produces (in .\dist):
      * EventHawk-1.3.0-Setup.exe  -- Inno Setup installer (~57 MB). Installs to
        Program Files with one-click Desktop + Start Menu shortcuts.
      * EventHawk-portable.7z      -- extract anywhere, run EventHawk.cmd.
    Bundles Python + PySide6 + DuckDB + PyArrow + every dependency and data file.
    End users need NOTHING installed.

    CLEAN-ROOM: this script never reads your local/global Python. It downloads a
    fresh Python "embeddable" build from python.org, HARD-FAILS unless python.exe
    is Authenticode-signed by the Python Software Foundation, bootstraps pip, and
    installs every dependency fresh from PyPI into an isolated runtime
    (PYTHONNOUSERSITE=1, so AppData\Roaming\Python is ignored).

    WHY NOT PyInstaller: its bootloader is an antivirus false-positive magnet.
    This ships the code-signed pythonw.exe and packages with Inno Setup (a
    trusted installer) into Program Files, so AV has no unsigned stub to flag.

    NOTE ON AGGRESSIVE AV (e.g. Kaspersky): some engines quarantine the Rust EVTX
    parser (evtx/_native.pyd) on fresh install. If that happens, whitelist the
    build folder ($WorkDir) and the install folder in your AV. This is a
    false positive on a legitimate open-source parser.

    Requirements: internet access, 7-Zip, Inno Setup 6
      (winget install JRSoftware.InnoSetup).
    Usage:   powershell -ExecutionPolicy Bypass -File build_standalone.ps1
#>
param(
    [string]$PyVersion = "3.14.4",
    [string]$WorkDir   = "$env:LOCALAPPDATA\eh-build",   # short path (avoids MAX_PATH)
    [string]$OutDir    = "$PSScriptRoot\dist",
    [string]$ISCC      = ""                              # optional explicit ISCC.exe path
)
$ErrorActionPreference = "Stop"
$env:PYTHONNOUSERSITE = "1"; $env:PYTHONPATH = ""       # isolate from local packages
$repo = $PSScriptRoot
$tag  = ($PyVersion -split '\.')[0..1] -join ''          # 3.14.4 -> 314
$dst  = Join-Path $WorkDir "EventHawk"

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

# 2 ── pip + all dependencies, fresh from PyPI, isolated --------------------
Write-Host "==> [2/6] Bootstrapping pip and installing requirements (isolated from local packages)"
"python$tag.zip`n.`nLib\site-packages`nimport site" | Set-Content "$dst\python$tag._pth" -Encoding ascii
Invoke-WebRequest "https://bootstrap.pypa.io/get-pip.py" -OutFile "$WorkDir\get-pip.py"
& "$dst\python.exe" "$WorkDir\get-pip.py" --no-warn-script-location -q
& "$dst\python.exe" -m pip install --no-warn-script-location -q -r "$repo\requirements.txt"

# 3 ── app code + icon + launcher -------------------------------------------
Write-Host "==> [3/6] App code + icon + launcher"
Copy-Item "$repo\evtx_tool" "$dst\evtx_tool" -Recurse -Force
Copy-Item "$repo\eventhawk_gui.py", "$repo\evtx_tool.py" $dst -Force
Copy-Item "$repo\evtx_tool\resources\images\eventhawk_logo.ico" "$dst\EventHawk.ico" -Force
"@echo off`r`nstart """" ""%~dp0pythonw.exe"" ""%~dp0eventhawk_gui.py"" %*" | Set-Content "$dst\EventHawk.cmd" -Encoding ascii

# 4 ── trim dead weight (keep every FEATURE + every dist-info) --------------
Write-Host "==> [4/6] Trimming dead weight"
$sp = "$dst\Lib\site-packages"
'pip', 'setuptools', 'wheel', 'pkg_resources', '_distutils_hack' | ForEach-Object {
    Remove-Item "$sp\$_" -Recurse -Force -ErrorAction SilentlyContinue }
# dist-info: keep them (duckdb etc. read their own metadata) EXCEPT build-only tools
Get-ChildItem $sp -Directory | Where-Object { $_.Name -match '^(pip|setuptools|wheel)-.*\.dist-info$' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $sp -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
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

# 5 ── portable archives (extract-and-run, no install) ----------------------
Write-Host "==> [5/6] Building portable archives"
$sevenZip = @("$env:ProgramFiles\7-Zip\7z.exe","${env:ProgramFiles(x86)}\7-Zip\7z.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($sevenZip) {
    # .7z: smallest; needs 7-Zip / WinRAR to extract.
    & $sevenZip a -t7z -mx=9 -m0=lzma2 -md=128m -ms=on "$OutDir\EventHawk-portable.7z" "$dst" | Out-Null
    Write-Host "    portable .7z: $([math]::Round((Get-Item "$OutDir\EventHawk-portable.7z").Length/1MB)) MB (needs 7-Zip)"
    # self-extracting .exe: double-click -> unpacks + runs EventHawk.cmd. No 7-Zip needed.
    $sfxMod = Join-Path (Split-Path $sevenZip) "7z.sfx"
    if (Test-Path $sfxMod) {
        $cfg = "$WorkDir\sfx.txt"
        @"
;!@Install@!UTF-8!
Title="EventHawk"
RunProgram="EventHawk\\EventHawk.cmd"
;!@InstallEnd@!
"@ | Set-Content $cfg -Encoding utf8
        $sfxExe = "$OutDir\EventHawk-portable.exe"
        $fs = [System.IO.File]::Create($sfxExe)
        foreach ($part in @($sfxMod, $cfg, "$OutDir\EventHawk-portable.7z")) {
            $bytes = [System.IO.File]::ReadAllBytes($part); $fs.Write($bytes, 0, $bytes.Length)
        }
        $fs.Close()
        Write-Host "    self-extractor .exe: $([math]::Round((Get-Item $sfxExe).Length/1MB)) MB (double-click to run)"
    }
} else { Write-Host "    7-Zip not found - skipping portable archives" -ForegroundColor Yellow }

# 6 ── Inno Setup installer -------------------------------------------------
Write-Host "==> [6/6] Building installer with Inno Setup"
if (-not $ISCC) {
    $ISCC = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe","$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $ISCC) { throw "Inno Setup not found. Install with: winget install JRSoftware.InnoSetup  (or pass -ISCC <path>)" }
& $ISCC "/DSourceDir=$dst" "/O$OutDir" "$repo\EventHawk.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compile failed (exit $LASTEXITCODE)" }

$setup = Join-Path $OutDir "EventHawk-1.3.0-Setup.exe"
Write-Host "`nDONE:" -ForegroundColor Green
Write-Host "  installer: $setup ($([math]::Round((Get-Item $setup).Length/1MB)) MB)" -ForegroundColor Green
if (Test-Path "$OutDir\EventHawk-portable.7z") { Write-Host "  portable : $OutDir\EventHawk-portable.7z" -ForegroundColor Green }
