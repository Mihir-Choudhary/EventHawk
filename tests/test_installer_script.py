"""The installer script (EventHawk.iss) matches what the release workflow and the user expect.

  - a licence page: LicenseFile names the repository's LICENSE (the wizard's Next
    stays disabled until "I accept the agreement" is chosen);
  - per-user by default, with the install-mode dialog, and /ALLUSERS allowed from
    the command line ("commandline"), as in the installer the user gave as the model;
  - every switch the workflow passes to Setup.exe is one Inno Setup knows.
Static: reads the files only.  The built installer is tested by the workflow
(silent install, smoke test, uninstall) and was driven through its wizard by hand
with UI Automation on 2026-11-21 (licence page blocks Next until accepted).
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def setup_value(iss, key):
    m = re.search(rf"^\s*{key}\s*=\s*(.+?)\s*$", iss, re.M | re.I)
    return m.group(1) if m else None


def main() -> int:
    iss = open(os.path.join(ROOT, "EventHawk.iss"), encoding="utf-8").read()
    wf = open(os.path.join(ROOT, ".github", "workflows", "build-release.yml"), encoding="utf-8").read()

    lic = setup_value(iss, "LicenseFile")
    check("LicenseFile is set (licence page before installing)", lic, str(lic))
    path = os.path.join(ROOT, lic) if lic else ""
    check("LicenseFile names an existing file", lic and os.path.isfile(path), path)
    check("LicenseFile is the repository's LICENSE", lic and os.path.normcase(os.path.abspath(path))
          == os.path.normcase(os.path.join(ROOT, "LICENSE")), str(lic))
    check("the licence page is not hidden", not re.search(r"^\s*DisableLicensePage\s*=\s*(yes|true|1)", iss, re.M | re.I))

    ovr = (setup_value(iss, "PrivilegesRequiredOverridesAllowed") or "").lower().split()
    check("PrivilegesRequiredOverridesAllowed keeps the install-mode dialog", "dialog" in ovr, str(ovr))
    check("/ALLUSERS and /CURRENTUSER allowed from the command line (commandline)", "commandline" in ovr, str(ovr))
    check("per-user by default (PrivilegesRequired=lowest)",
          (setup_value(iss, "PrivilegesRequired") or "").lower() == "lowest")

    m = re.search(r"^\[UninstallDelete\](.*?)(?=^\[|\Z)", iss, re.M | re.S)
    udel = {n.lower() for n in re.findall(r'Name:\s*"\{app\}\\([^"]+)"', m.group(1) if m else "")}
    check("uninstall removes the code folders whole (bytecode caches in every package)",
          {"evtx_tool", "sentinel", "lib"} <= udel, str(sorted(udel)))
    check("uninstall keeps profiles, logs and the per-user data folder",
          not any(n.split("\\")[0] in ("profiles", "evtx_tool_logs") for n in udel)
          and "{localappdata}" not in (m.group(1).lower() if m else ""), str(sorted(udel)))

    known = {"/VERYSILENT", "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/ALLUSERS",
             "/DIR", "/LOG", "/TASKS", "/MERGETASKS", "/NOICONS", "/LANG", "/GROUP", "/NOCANCEL"}
    m = re.search(r"- name: Test the installer.*?(?=\n\s*- (?:name|uses):)", wf, re.S)
    step = m.group(0) if m else ""
    used = {s.upper() for s in re.findall(r'"(/[A-Za-z]+)', step)}
    check("every Setup.exe switch in the workflow's installer step is an Inno Setup switch",
          {"/VERYSILENT", "/CURRENTUSER", "/DIR"} <= used and used <= known,
          f"used {sorted(used)}, unknown {sorted(used - known)}")

    n = sum(CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
