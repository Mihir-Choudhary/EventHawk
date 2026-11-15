"""Profile Event IDs accept the ranges their hint shows; the picker search keeps ticks.

Gemini audit 11-03 / 3-12 (High / Medium):
- the Profile Editor's hint says "4624,4625  or  4624-4630!4627", but a range
  was dropped silently and saved as event_ids [] -- which means "every Event
  ID"; "eventhawk profiles create --event-ids 4624-4626" did the same;
- the Profile Editor rewrote an operator it does not list to "contains";
- the Picker's search box unticked every item it hid and, when cleared,
  ticked ALL items, losing the analyst's selection.

Expected: "4624-4630!4627" saves [4624..4630] without 4627; a bad token or an
exclusion-only entry is refused (not saved as []); the CLI refuses a bad
token and expands a range; an unlisted operator is kept; after typing and
clearing a search, the picker's ticks are what they were.
Synthetic values only.
"""
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    os.chdir(tempfile.mkdtemp(prefix="profeid_"))   # user profiles go to ./profiles

    from PySide6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication([])
    warned = []
    QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2] if len(a) > 2 else ""))
    QMessageBox.critical = staticmethod(lambda *a, **k: warned.append(a[2] if len(a) > 2 else ""))
    from evtx_tool.gui.profile_editor import ProfileEditorDialog

    def editor(eids, op="contains"):
        d = ProfileEditorDialog(profile=None)
        d._inp_name.setText("T")
        d._inp_event_ids.setText(eids)
        d._add_condition({"name": "X", "operator": op, "value": "1"})
        return d
    d = editor("4624-4630!4627")
    p = d._get_profile_dict()
    check("'4624-4630!4627' saves 4624..4630 without 4627",
          p["event_ids"] == [4624, 4625, 4626, 4628, 4629, 4630], str(p["event_ids"]))
    for bad in ("4624,abc", "!4625"):
        warned.clear()
        d = editor(bad)
        saved = []
        import evtx_tool.profiles.manager as PMm
        orig = PMm.ProfileManager.create
        PMm.ProfileManager.create = lambda self, prof: saved.append(prof)
        try:
            d._on_save()
        finally:
            PMm.ProfileManager.create = orig
        check(f"{bad!r} is refused, not saved as 'every Event ID'", not saved and warned,
              f"saved {saved[:1]}, warned {warned[:1]}")
    d = editor("4624", op="is between")
    p = d._get_profile_dict()
    check("an operator the editor does not list is kept", p["conditions"][0]["operator"] == "is between",
          p["conditions"][0]["operator"])

    from click.testing import CliRunner
    import evtx_tool.cli as C
    r = CliRunner().invoke(C.cli, ["profiles", "create", "--name", "CliT", "--event-ids", "4624-4626", "--description", "", "--sources", ""])
    from evtx_tool.profiles.manager import ProfileManager
    prof = ProfileManager().get("CliT")

    check("CLI 'profiles create --event-ids 4624-4626' saves the range",
          prof is not None and prof.get("event_ids") == [4624, 4625, 4626], f"exit {r.exit_code}: {prof and prof.get('event_ids')} {r.output[-120:]}")
    r = CliRunner().invoke(C.cli, ["profiles", "create", "--name", "CliBad", "--event-ids", "4624,abc", "--description", "", "--sources", ""])
    check("CLI refuses a bad Event ID token", r.exit_code != 0, f"exit {r.exit_code}: {r.output[-120:]}")

    from evtx_tool.profiles.manager import ProfileManager as _PM
    v = _PM._validate_profile({"name": "Z", "event_ids": ["0", "4624", "4625.0"]})
    check("a saved Event ID \"0\" is kept (3-02)", v["event_ids"] == [0, 4624, 4625], str(v["event_ids"]))

    from evtx_tool.gui.picker_dialog import PickerDialog
    pd = PickerDialog("Computers", {"HOST-01": 10, "HOST-02": 5, "HOST-03": 2}, pre_selected={"HOST-01"})
    before = sorted(pd.selected_values())
    pd._search.setText("HOST-02")
    app.processEvents()
    pd._search.setText("")
    app.processEvents()
    after = sorted(pd.selected_values())
    check("typing and clearing a picker search keeps the ticks", before == after == ["HOST-01"], f"{before} -> {after}")
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
