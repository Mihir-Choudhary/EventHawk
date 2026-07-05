# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for EventHawk.exe — a thin launcher (see launcher.py).
#
# The launcher only touches the standard library (os, sys, subprocess,
# ctypes, winreg), so the dependency graph is tiny. Everything below is
# tuned to keep the one-file EXE as small as possible:
#   * optimize=2   — bundle byte-code with docstrings/asserts stripped (-OO)
#   * excludes     — nothing here is imported by the launcher, so dropping it
#                    strips megabytes of GUI/DB/crypto/test stdlib weight the
#                    frozen interpreter would otherwise carry. Safe because the
#                    bundled Python only runs launcher.py; the real app runs
#                    under the user's *system* Python.
#   * upx=True     — compress the Python DLL + extension modules
#
# Build:  pyinstaller EventHawk.spec
# (add  --upx-dir <path>  if `upx` is not on PATH)
#
# strip=False: the `strip` utility ships with binutils, not Windows, so
# enabling it aborts the build there. UPX already handles compression.

_EXCLUDES = [
    # GUI / imaging toolkits — the launcher never imports them
    'tkinter', '_tkinter', 'turtle', 'PIL',
    # Crypto / compression / DB extension modules (large .pyd, unused here)
    'sqlite3', 'ssl', '_ssl', 'hashlib', '_hashlib',
    'bz2', '_bz2', 'lzma', '_lzma', 'unicodedata',
    'socket', '_socket', 'select', 'selectors',
    'decimal', '_decimal',
    # Pure-stdlib packages the launcher does not touch
    'email', 'html', 'http', 'xml', 'xmlrpc', 'pydoc', 'pdb',
    'doctest', 'unittest', 'curses',
    # Packaging tooling that occasionally leaks into the graph
    'distutils', 'setuptools', 'pip',
]

a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=_EXCLUDES,
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='EventHawk',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='evtx_tool/resources/images/eventhawk_logo.ico',
    version='version_info.txt',
)
