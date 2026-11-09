"""The IOC tab's "This File" scope shows that file's IOCs (Codex DOC-5).

It always showed the collection's IOCs (a file with 1 IOC showed 2 under
"This File"), while ATT&CK has its own per-file branch.  Expected, Normal
separate view: "This File" = the IOCs of the tab's own events, with the
collection's scores kept; "All Files" = every IOC.  Synthetic data only.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(sf, rid, ip):
    return {"event_id": 3, "provider": "Microsoft-Windows-Sysmon", "channel": "Sysmon", "computer": "PC",
            "source_file": sf, "record_id": rid, "timestamp": f"2024-01-02T03:04:0{rid}Z",
            "event_data": {"DestinationIp": ip}}


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    a = [ev("a.evtx", 1, "10.1.1.1")]
    b = [ev("b.evtx", 2, "10.2.2.2")]
    w = mw.MainWindow()
    allx = extract_iocs(a + b)
    for en in allx.get("ipv4", []):
        en["score"] = 77
    w._iocs = allx
    w._view_mode = "separate"
    w._file_tabs["a.evtx"] = mw.FileTabState("a.evtx", "a.evtx", a, [], None, None, None)
    w._active_file_tab = "a.evtx"
    w._analysis_scope = "file"
    w._refresh_iocs_tab()
    txt_file = w._lbl_ioc_summary.text()
    w._analysis_scope = "all"
    w._refresh_iocs_tab()
    txt_all = w._lbl_ioc_summary.text()
    n_all = sum(len(v) for v in allx.values() if isinstance(v, list))
    n_a = sum(len(v) for v in extract_iocs(a).values() if isinstance(v, list))
    check("All Files: every IOC", txt_all.startswith(f"{n_all} unique"), f"{txt_all[:30]} vs {n_all}")
    check("This File: only the file's IOCs", n_a < n_all and txt_file.startswith(f"{n_a} unique"),
          f"{txt_file[:30]} vs {n_a}")
    st = w._file_tabs["a.evtx"]
    ips = [e.get("value") for e in (st.iocs or {}).get("ipv4", [])]
    check("the file's IOC is its own value, with the collection's score kept",
          ips == ["10.1.1.1"] and st.iocs["ipv4"][0].get("score") == 77, str(st.iocs and st.iocs.get("ipv4")))
    w._file_tabs.clear()
    w.close()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
