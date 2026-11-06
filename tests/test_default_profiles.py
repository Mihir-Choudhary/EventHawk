"""Built-in profiles name exact providers, so a profile never pulls in unrelated logs (2026-11-07 rework).

A profile source matches as a case-insensitive substring of provider or
channel.  The old defaults used "Security" and "System": "Security" also
matched SecurityCenter, Security-Mitigations, Security-SPP and
LessPrivilegedAppContainer, so Process Creation showed 9,041 events that were
not process events; "System" matched every System-log provider.
Expected for every built-in profile: it loads, has a unique name, names at
least one source, and no source is a bare log name (Security, System,
Application, Setup).  Optional argument: a folder of profile JSON files
(default: evtx_tool/profiles/defaults).
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
BROAD = {"security", "system", "application", "setup"}


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.profiles.manager import ProfileManager
    folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evtx_tool", "profiles", "defaults")
    files = sorted(glob.glob(os.path.join(folder, "*.json")))
    check("built-in profiles found", len(files) >= 20, f"{len(files)} files")
    profiles = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            profiles.append((os.path.basename(f), ProfileManager._validate_profile(json.load(fh))))
    names = [p["name"] for _, p in profiles]
    check("every profile has a unique name", len(set(names)) == len(names))
    no_src = [f for f, p in profiles if not p["sources"]]
    check("every profile names at least one source", not no_src, str(no_src))
    broad = [(f, s) for f, p in profiles for s in p["sources"] if s.strip().lower() in BROAD]
    check("no source is a bare log name (Security, System, ...)", not broad, f"{len(broad)}: {broad[:4]}")
    dup = [f for f, p in profiles if len(set(p["event_ids"])) != len(p["event_ids"])]
    check("no profile lists an Event ID twice", not dup, str(dup))
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
