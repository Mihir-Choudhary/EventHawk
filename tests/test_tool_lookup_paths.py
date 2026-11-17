"""Outside programs are found only where they should be (Gemini 13-03).

1. find_hayabusa() used shutil.which, which on Windows looks in the current
   directory first: a hayabusa.exe / hayabusa.cmd planted in the folder EventHawk
   was started from (often the evidence folder) would be run.
2. A single selected log whose relative path starts with "-" was passed to
   Hayabusa as is, where it reads as an option.
3. The launcher searched per-user Pythons first and stopped at the first hive
   with any Python, so an old per-user 3.9 beat a machine-wide 3.12; a
   free-threaded build (3.13t), which install.bat refuses, could be picked.

Expected: 1. no program is taken from the current directory or a relative PATH
entry; one in an absolute PATH folder is found. 2. the path handed to Hayabusa
never starts with "-". 3. the newest regular Python across both hives.
Synthetic folders and a fake registry only.
"""
import os
import shutil
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def touch(p):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "wb").close()


def main() -> int:
    from evtx_tool.analysis import hayabusa_runner as H
    base = tempfile.mkdtemp(prefix="tl_")
    old_cwd, old_path = os.getcwd(), os.environ.get("PATH", "")
    try:
        cwd = os.path.join(base, "evidence")
        good = os.path.join(base, "tools")
        exe = "hayabusa.exe" if sys.platform == "win32" else "hayabusa"
        touch(os.path.join(cwd, exe))
        touch(os.path.join(cwd, "hayabusa.cmd"))
        os.makedirs(good)
        os.chdir(cwd)
        saved_common = (H._COMMON_PATHS_WIN, H._COMMON_PATHS_LINUX)
        H._COMMON_PATHS_WIN, H._COMMON_PATHS_LINUX = [], []
        try:
            os.environ["PATH"] = good + os.pathsep + "." + os.pathsep
            got = H.find_hayabusa()
            check("a hayabusa in the current folder is not used", got is None or os.path.dirname(got) != cwd, str(got))
            touch(os.path.join(good, exe))
            if sys.platform != "win32":
                os.chmod(os.path.join(good, exe), 0o755)
            got = H.find_hayabusa()
            check("one in an absolute PATH folder is found", got and os.path.normcase(got) == os.path.normcase(os.path.join(good, exe)), str(got))
        finally:
            H._COMMON_PATHS_WIN, H._COMMON_PATHS_LINUX = saved_common

        touch(os.path.join(cwd, "-weird.evtx"))
        flag, val, tmp = H._resolve_input(["-weird.evtx"])
        check("a log named '-weird.evtx' is not handed over as an option", not str(val).startswith("-"), f"{flag} {val}")
        check("...and still names that log", os.path.normcase(os.path.abspath(val)) == os.path.normcase(os.path.join(cwd, "-weird.evtx")), val)
    finally:
        os.chdir(old_cwd)
        os.environ["PATH"] = old_path

    # 3. the launcher, with a fake registry
    import launcher
    hkcu, hklm = object(), object()
    py = {}
    for hive, ver in ((hkcu, "3.9"), (hklm, "3.12"), (hklm, "3.13t"), (hklm, "3.11")):
        d = os.path.join(base, "py", f"{id(hive)}_{ver}")
        touch(os.path.join(d, "pythonw.exe"))
        py.setdefault(hive, {})[ver] = d

    class Key:
        def __init__(self, hive, path):
            self.hive, self.path = hive, path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    fake = types.ModuleType("winreg")
    fake.HKEY_CURRENT_USER, fake.HKEY_LOCAL_MACHINE = hkcu, hklm

    def OpenKey(parent, sub):
        if isinstance(parent, Key):
            ver = sub.split("\\")[0]
            if ver not in py.get(parent.hive, {}):
                raise OSError("no key")
            return Key(parent.hive, ver)
        if sub != r"SOFTWARE\Python\PythonCore" or parent not in py:
            raise OSError("no key")
        return Key(parent, sub)

    def EnumKey(k, i):
        vs = list(py[k.hive])
        if i >= len(vs):
            raise OSError("end")
        return vs[i]

    def QueryValue(k, name):
        return py[k.hive][k.path]
    fake.OpenKey, fake.EnumKey, fake.QueryValue = OpenKey, EnumKey, QueryValue
    saved = sys.modules.get("winreg")
    sys.modules["winreg"] = fake
    try:
        got = launcher._find_pythonw()
    finally:
        if saved is not None:
            sys.modules["winreg"] = saved
    want = os.path.join(py[hklm]["3.12"], "pythonw.exe")
    check("the launcher picks the newest regular Python of both hives (3.12)", got == want, str(got))
    shutil.rmtree(base, ignore_errors=True)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
