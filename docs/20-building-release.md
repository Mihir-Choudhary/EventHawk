# Building the thin Windows launcher

This guide describes the checked-in build configuration, not a verified downloadable release. Build/publish operations are maintainer actions; source-level inspection alone does not prove that a packaged application works on a clean machine.

## Thin launcher

`EventHawk.spec` builds `launcher.py`. It produces a windowed EventHawk.exe that locates system Python and runs adjacent `evtx_tool.py gui`. It does **not** bundle EventHawk's application dependencies. Its size is not guaranteed.

With PyInstaller available in the chosen build environment, from the repository root:

```powershell
py -3.12 -m PyInstaller EventHawk.spec
```

Expected spec output is `dist/EventHawk.exe`. The spec uses the application icon and `version_info.txt`; changing a README version does not change executable metadata.

The executable must sit beside evtx_tool.py. A usable application layout also needs the evtx_tool package, its resources/default profiles, the required dependencies under system Python, and the separate sentinel package for Sentinel. Keep root launch scripts if your package advertises them. Compiling only the launcher or distributing only that EXE is insufficient.

## Current workflow limitation

`.github/workflows/build-release.yml` builds the thin launcher and assembles a ZIP. Its assembly list copies the executable, requirements/install/run files, README and default profile files, but **omits evtx_tool.py and the application package trees**. As written, that list is not a complete runnable EventHawk distribution. Do not use a successful workflow build as evidence that the ZIP launches.

This documentation update does not change that workflow. A maintainer must correct/stage a complete application before treating its output as a usable release, then verify it on a clean target. For the embedded-runtime path use [standalone build](21-building-standalone.md).

## Release verification

Before publication, inspect the staged files and test launch, parsing, both storage modes, profile loading, optional-tool behavior and each advertised export format. Check that resources and the sentinel package are present and that advertised dependency/runtime requirements match the actual artifact. Exclude user logs, EVTX inputs, Parquet sessions, baseline artifacts, runtime logs and local developer journals.

The workflow has a manual trigger and a v-prefixed tag trigger; the tag path publishes a GitHub release. Publishing is separate from local build verification. No publishing command is needed to test a local package.

See [installation](01-installation.md) and [tests](22-testing.md).
