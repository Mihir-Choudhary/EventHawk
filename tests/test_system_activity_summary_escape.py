"""System Activity's summary shows a Computer name as text, never as markup.

Gemini audit 8-16 (Low): the summary label is rich text and the host name
went into it unescaped, so a Computer value holding "<img ...>" or "&" was
parsed as HTML (the name shown wrong, markup run).

Expected: the label holds the escaped name.  Synthetic events.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_around_pivot as T                                       # noqa: E402
from test_wifi_boot_barrier import kernel_boot                      # noqa: E402

HOST = "SYNTH<img src='x'>&HOST"


def main() -> int:
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    from evtx_tool.analysis import system_activity as sa
    from evtx_tool.gui.system_activity_dialog import SystemActivityDialog
    evs = [kernel_boot(HOST, 1, 0, start=0), kernel_boot(HOST, 2, 3600, start=3600)]
    res = sa.build([e for e in evs if sa.relevant(e)])
    dlg = SystemActivityDialog(res, digits=0, events=evs)
    dlg._summary(res["hosts"][0])
    txt = dlg._lbl_summary.text()
    dlg.close()
    ok = "&lt;img src=&#x27;x&#x27;&gt;&amp;HOST" in txt and "<img" not in txt
    print(f"  {'PASS' if ok else 'FAIL'}  the host name is escaped in the summary  -- {txt[:120]!r}")
    print(f"{int(ok)}/1 checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
