"""Profiles: a read-only folder does not crash, names resolve exactly, files never collide.

Gemini audit 11-05 / 11-17 / 11-20 / 11-10 / 13-07, evtx_tool/profiles/manager.py:
- 11-05: ProfileManager (and the CLI log folder) crashed when the working
  folder is read-only (an all-users install under Program Files);
- 11-17: "-p Activity" silently took 1 of several matching profiles, and an
  empty name matched every profile;
- 11-20: a JSON file whose root is not an object raised TypeError; an empty
  name was accepted;
- 11-10 / 13-07: "RDP:Inbound" and "RDP/Inbound" were written to one file
  (one profile replaced the other), and a name like "CON" gave a reserved
  Windows file name; editing a custom profile's Name was silently ignored.

Expected: each handled.  Synthetic profiles in temporary folders.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.profiles.manager as M
    base = Path(tempfile.mkdtemp(prefix="pm_"))
    os.environ["LOCALAPPDATA"] = str(base / "lad")

    real_mkdir = Path.mkdir

    def ro_mkdir(self, *a, **k):
        if "readonly" in str(self):
            raise PermissionError(13, "Access is denied", str(self))
        return real_mkdir(self, *a, **k)
    Path.mkdir = ro_mkdir
    try:
        try:
            pm = M.ProfileManager(user_dir=base / "readonly" / "profiles")
            ok = len(pm.list_names()) > 0
            where = str(pm._user_dir)
        except Exception as exc:
            ok, where = False, f"{type(exc).__name__}: {exc}"
    finally:
        Path.mkdir = real_mkdir
    check("a read-only profile folder does not crash (built-ins load)", ok, where)

    pm = M.ProfileManager(user_dir=base / "u")
    for n in ("Act One", "Act Two"):
        pm.create({"name": n, "event_ids": [1]})
    try:
        pm.build_filter(["Act"], strict=True)
        amb = False
    except M.ProfileNotFoundError as exc:
        amb = "Act One" in str(exc) and "Act Two" in str(exc)
    check("an ambiguous partial name is refused, naming the candidates", amb)
    try:
        pm.build_filter([""], strict=True)        # "" is in every name
        blank = False
    except M.ProfileNotFoundError:
        blank = True
    check("a blank name is refused", blank)

    bad = base / "list.json"
    bad.write_text(json.dumps([1, 2]), encoding="utf-8")
    try:
        pm.import_profile(str(bad))
        nd = False
    except ValueError:
        nd = True
    except Exception as exc:
        nd = False
        print("   ", type(exc).__name__, exc)
    check("a JSON file that is not an object is refused (ValueError)", nd)
    try:
        pm.create({"name": "   ", "event_ids": [1]})
        en = False
    except ValueError:
        en = True
    check("an empty name is refused", en)

    a = pm.create({"name": "RDP:Inbound", "event_ids": [1149]})
    b = pm.create({"name": "RDP/Inbound", "event_ids": [4624]})
    check("two names that sanitise alike get two files",
          a["_source_path"] != b["_source_path"] and Path(a["_source_path"]).exists() and Path(b["_source_path"]).exists(),
          f"{Path(a['_source_path']).name} / {Path(b['_source_path']).name}")
    pm2 = M.ProfileManager(user_dir=base / "u")
    check("...and both load back", {"RDP:Inbound", "RDP/Inbound"} <= set(pm2.list_names()))
    c = pm.create({"name": "CON", "event_ids": [1]})
    check("a reserved Windows name is not used as the file name", Path(c["_source_path"]).stem.upper() != "CON",
          Path(c["_source_path"]).name)

    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.profile_editor import ProfileEditorDialog
    try:
        dlg = ProfileEditorDialog(profile=pm.get("Act One"), parent=None)
    except TypeError:
        dlg = ProfileEditorDialog(pm.get("Act One"))
    check("editing a custom profile: Name is read-only (update keeps names)", dlg._inp_name.isReadOnly())
    dlg.close()
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
