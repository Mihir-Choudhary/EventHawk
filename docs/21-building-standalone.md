# Building an embedded-runtime Windows package

`build_standalone.ps1` stages an embeddable Windows Python runtime and the application. This is separate from the [thin launcher](20-building-release.md). These are source-verified build instructions, not a claim that a new installer has been built or clean-machine tested.

## Inputs and operation

The script accepts **PyVersion**, **WorkDir**, **OutDir** and **ISCC**. Its current PyVersion default is 3.14.4; that is a script setting, not a guarantee of remote availability or compatible dependency wheels. It downloads Python and pip bootstrap content and installs requirements, so building needs network access and the appropriate build environment.

**WorkDir is disposable:** the script recursively removes an existing WorkDir before staging. Choose a dedicated build directory containing nothing you need. Read the script before running it. OutDir receives generated artifacts. Inno Setup 6 is needed for the installer; ISCC can name its compiler explicitly.

From the repository root, after preparing those prerequisites:

```powershell
.\build_standalone.ps1
```

## What the source stages

The script checks the downloaded python.exe's Authenticode status and Python Software Foundation signer before proceeding. It installs requirements.txt, copies evtx_tool and sentinel plus evtx_tool.py/eventhawk_gui.py, adds an icon and EventHawk.cmd, and trims selected runtime files. The final Python path file isolates the deployed runtime from user site packages.

Copying the sentinel package does not install optional pySigma: the script installs the main requirements, not sentinel/requirements.txt. Sentinel's heuristic pre-tagging therefore requires separate dependency preparation if advertised; non-Sigma analysis has its own path.

When 7-Zip is found, the script produces EventHawk-portable.7z; a self-extracting portable EXE also depends on its SFX module. Inno Setup uses EventHawk.iss and currently names the installer EventHawk-2.0.0-Setup.exe. These names/defaults come from source; do not infer the next release version or availability from them. No package-size guarantee is made.

## Verify the actual artifact

Test extraction/installation and startup without relying on system Python or developer-installed packages. Verify dependencies after trimming, icons/resources/default profiles, parsing, Juggernaut workers, session tools, Sentinel and exports. Test launch from outside the source directory. A signature check on Python alone does not authenticate all downloaded dependencies or prove the application works.

EventHawk.iss offers per-user installation by default with an optional elevated installation mode and creates shortcuts to the bundled Python entry script. Review its uninstall cleanup too: it removes the application's local EventHawk directory, which includes GUI logs. Preserve needed diagnostic material before uninstalling.

Do not claim a build passed unless its actual output was launched and tested. See [testing](22-testing.md) and [installation](01-installation.md).
