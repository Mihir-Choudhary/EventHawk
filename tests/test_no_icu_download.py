"""Column values never download a DuckDB extension, and look the zone up once.

Gemini audit 4-08 (Medium): _system_tz_name() did "LOAD icu" and, when that
failed, "INSTALL icu" -- a download from the internet by an offline forensic
tool -- and opened a fresh DuckDB connection on every call (every popup).

Expected: when LOAD icu fails, no INSTALL is attempted and the function falls
back (None or an IANA name); a second call opens no connection.
No network; duckdb.connect is replaced by a recorder.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    os.environ.pop("TZ", None)
    import duckdb
    log = {"connects": 0, "sql": []}

    class FakeCon:
        def execute(self, sql, *a):
            log["sql"].append(sql)
            if "icu" in sql.lower():
                raise RuntimeError("extension not available (offline)")
            raise RuntimeError("no")

        def close(self):
            pass

    def fake_connect(*a, **k):
        log["connects"] += 1
        return FakeCon()
    duckdb.connect = fake_connect
    import evtx_tool.gui.jm_col_worker as J
    if hasattr(J._system_tz_name, "cache_clear"):
        J._system_tz_name.cache_clear()
    J._system_tz_name()
    check("no INSTALL is attempted when LOAD icu fails",
          not any("install" in s.lower() for s in log["sql"]), str(log["sql"]))
    n1 = log["connects"]
    J._system_tz_name()
    check("a second call opens no new connection", log["connects"] == n1, f"{n1} -> {log['connects']}")
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
