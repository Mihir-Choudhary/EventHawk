"""Advanced text search must find EVERYTHING, identically in both modes.

The haystack used to cover seven System fields and EventData VALUES only. So a
term the analyst could plainly see in the detail panel -- a record ID, a PID, a
keyword mask, an EventData FIELD NAME, or Provider@EventSourceName -- returned
nothing, with no indication the search scope was narrower than the data.

Every check compares Juggernaut against normal mode, because a search that
answers differently depending on mode is its own defect.

Run: QT_QPA_PLATFORM=offscreen python tests/test_search_coverage.py
"""
import os, sys, glob, json, itertools, shutil, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.core.parser import iter_events
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel

    LOGS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    src = os.path.join(LOGS, "Application.evtx")
    if not os.path.exists(src):
        cands = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
        if not cands:
            print("no logs — skipping"); return 0
        src = cands[0]

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    evs = list(itertools.islice(iter_events(src), 40000))
    print(f"{len(evs):,} events from {os.path.basename(src)}")

    check("parser now captures EventSourceName",
          any(e.get("event_source_name") for e in evs),
          str(sorted({e.get("event_source_name","") for e in evs} - {""})[:3]))

    nm = EventTableModel(); nm.set_events(evs)
    npx = EventFilterProxyModel(); npx.setSourceModel(nm)
    def norm(term):
        npx.set_advanced_filter({"text_search": term}); n = npx.rowCount()
        npx.set_advanced_filter(None); return n

    tmp = tempfile.mkdtemp(prefix="search_cov_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run([src])
        table = load_arrow_table(pq)
        check("JM Arrow table carries event_source_name",
              "event_source_name" in table.column_names, str(table.column_names[:9]))
        jm_model = ArrowTableModel(table, parquet_dir=pq)
        def settle():
            loop = QEventLoop(); d = {"h": False}
            def fin(): d["h"] = True; loop.quit()
            jm_model.busy_finished.connect(fin); QTimer.singleShot(120000, loop.quit)
            if not d["h"]: loop.exec()
            try: jm_model.busy_finished.disconnect(fin)
            except Exception: pass
        settle()
        def jm(term):
            jm_model.apply_filter({"text_search": term}); settle(); n = jm_model.rowCount()
            jm_model.clear_filter(); settle(); return n

        # pick real values straight out of the data so nothing is hypothetical
        e0 = next(e for e in evs if e.get("event_source_name"))
        with_pid = next((e for e in evs if str(e.get("process_id") or "").strip()
                         not in ("", "0", "None")), None)
        ed_named = next((e for e in evs if isinstance(e.get("event_data"), dict)
                         and any(k for k in e["event_data"] if not k.startswith("#")
                                 and k not in ("Data", "Binary"))), None)
        field_name = None
        if ed_named:
            field_name = next(k for k in ed_named["event_data"]
                              if not k.startswith("#") and k not in ("Data", "Binary"))

        cases = [
            ("EventSourceName", e0["event_source_name"]),
            ("record_id",       str(evs[5]["record_id"])),
            ("keywords",        str(evs[0].get("keywords") or "")),
            ("provider Name",   e0.get("provider") or ""),
            ("channel",         evs[0].get("channel") or ""),
        ]
        if with_pid:
            cases.append(("process_id", str(with_pid["process_id"])))
        if field_name:
            cases.append(("EventData FIELD NAME", field_name))

        print(f"\n  {'field':<22} {'term':<34} {'JM':>7} {'NORMAL':>7}")
        for label, term in cases:
            if not term:
                continue
            a, b = jm(term), norm(term)
            print(f"  {label:<22} {term[:32]!r:<34} {a:>7} {b:>7}")
            check(f"{label} is findable", a > 0 and b > 0, f"jm={a} normal={b}")
            check(f"{label} agrees across modes", a == b, f"jm={a} normal={b}")

        # JSON-shaped and non-ASCII terms: normal mode serialises event_data
        # with Python's json, JM with orjson.  Separator and \uXXXX escaping
        # differences would make the same query hit in one mode and miss in the
        # other, which is worse than missing in both.
        import json as _j
        def _first_str_pair(o):
            """Any (key, str-value) pair, at any depth."""
            if isinstance(o, dict):
                for k, v in o.items():
                    if isinstance(k, str) and isinstance(v, str) and v.strip() \
                       and not k.startswith("#"):
                        return k, v
                for v in o.values():
                    r = _first_str_pair(v)
                    if r:
                        return r
            elif isinstance(o, (list, tuple)):
                for i in o:
                    r = _first_str_pair(i)
                    if r:
                        return r
            return None
        pair = next((p for p in (_first_str_pair(e.get("event_data") or {})
                                 for e in evs) if p), None)
        check("found a JSON pair to test encoder parity with", pair is not None,
              "no string-valued EventData field in the sample")
        if pair:
            _k, _v = pair
            frag = _j.dumps({_k: _v}, separators=(",", ":"),
                            ensure_ascii=False)[1:-1]   # 'key":"value'
            a, b = jm(frag), norm(frag)
            print(f"  {'json fragment':<22} {frag[:32]!r:<34} {a:>7} {b:>7}")
            check("JSON-shaped term is findable at all", a > 0 and b > 0,
                  f"jm={a} normal={b}")
            check("JSON-shaped term agrees across modes", a == b, f"jm={a} normal={b}")

        # ── JM quick search must have the SAME coverage as Advanced ──────
        # apply_text_filter used to search the Arrow columns only, so EventData
        # field names and container keys were invisible to the toolbar box
        # while the Advanced Filter found them: the same term, two answers.
        print("\n  quick (toolbar) vs advanced, same terms:")
        for label, term in cases:
            if not term:
                continue
            jm_model.apply_text_filter(term); settle(); q = jm_model.rowCount()
            jm_model.apply_text_filter(""); settle()
            a = jm(term)
            print(f"    {label:<22} quick={q:>7}  advanced={a:>7}")
            check(f"quick search matches advanced for {label}", q == a,
                  f"quick={q} advanced={a}")

        # ── the two text legs must AND, not replace each other ───────────
        t1, t2 = cases[0][1], "Application"
        if t1 and t2:
            jm_model.apply_filter({"text_search": t1}); settle()
            only_adv = jm_model.rowCount()
            jm_model.apply_text_filter(t2); settle()
            both = jm_model.rowCount()
            jm_model.apply_text_filter(""); settle()
            back = jm_model.rowCount()
            jm_model.clear_filter(); settle()
            check("quick + advanced compose (AND), neither is dropped",
                  both <= only_adv, f"adv={only_adv} adv+quick={both}")
            check("emptying the quick box restores the advanced-only result",
                  back == only_adv, f"{back} vs {only_adv}")

        # clearing the ADVANCED filter must not silently empty the quick box
        jm_model.apply_text_filter(t2); settle(); q_only = jm_model.rowCount()
        jm_model.clear_filter(); settle()
        check("clear_filter() keeps the quick search applied",
              jm_model.rowCount() == q_only, f"{jm_model.rowCount()} vs {q_only}")
        jm_model.apply_text_filter(""); settle()

        # ── both timestamp renderings must be findable ───────────────────
        # JM stores "YYYY-MM-DD HH:MM:SS.ffffff"; the raw EVTX and most other
        # tooling render "YYYY-MM-DDTHH:MM:SS.ffffffZ". Each mode used to find
        # only its own form, so a pasted timestamp hit in one and missed in the
        # other.
        _ts_iso = next((e["timestamp"] for e in evs if e.get("timestamp")), "")
        if _ts_iso:
            _ts_space = _ts_iso.replace("T", " ").rstrip("Z")
            for label, form in (("ISO (…T…Z)", _ts_iso), ("space form", _ts_space)):
                a, b = jm(form), norm(form)
                print(f"  {'timestamp ' + label:<22} {form[:32]!r:<34} {a:>7} {b:>7}")
                check(f"timestamp {label} is findable", a > 0 and b > 0,
                      f"jm={a} normal={b}")
                check(f"timestamp {label} agrees across modes", a == b,
                      f"jm={a} normal={b}")

        # ── a duplicated record must not be returned twice ───────────────
        # Phase 2 joins against the Parquet shards. A plain JOIN emitted one row
        # per matching PARQUET row, so an event whose (record_id, source_file)
        # appeared twice came back twice -- and include+exclude then summed to
        # MORE than the dataset. A semi-join keeps it to one row per candidate.
        _base = jm_model.rowCount()
        _t = cases[0][1]
        if _t:
            jm_model.apply_filter({"text_search": _t}); settle()
            _inc = jm_model.rowCount()
            _ids = jm_model._display_table["row_id"].to_pylist()
            jm_model.clear_filter(); settle()
            jm_model.apply_filter({"text_search": _t, "text_exclude": True}); settle()
            _exc = jm_model.rowCount()
            jm_model.clear_filter(); settle()
            check("no row is returned twice by a text search",
                  len(_ids) == len(set(_ids)), f"{len(_ids)} rows, {len(set(_ids))} unique")
            check("include + exclude == the whole dataset (no double counting)",
                  _inc + _exc == _base, f"{_inc}+{_exc} vs {_base}")

        # ── every SEARCH OPTION must agree across modes, not just plain
        # substring.  Regex especially: Normal Mode compiles with Python's re,
        # Juggernaut runs DuckDB regexp_matches -- two different engines that
        # must not disagree about which events match.
        _opts = [
            ("EXCLUDE",              {"text_search": "svchost", "text_exclude": True}),
            ("case-sensitive",       {"text_search": "MsiInstaller", "case_sensitive": True}),
            ("case-sens wrong case", {"text_search": "msiinstaller", "case_sensitive": True}),
            ("multi-term AND",       {"text_search": ["Application", "MsiInstaller"],
                                      "search_mode": "AND"}),
            ("multi-term OR",        {"text_search": ["MsiInstaller", "vmauthd"],
                                      "search_mode": "OR"}),
            ("regex",                {"text_search": "Msi.*ller", "text_regex": True}),
            ("regex char class",     {"text_search": "Msi[Ii]nstaller", "text_regex": True}),
            ("regex alternation",    {"text_search": "vmauthd|MsiInstaller", "text_regex": True}),
            ("regex EXCLUDE",        {"text_search": "Msi.*ller", "text_regex": True,
                                      "text_exclude": True}),
            ("backslash path",       {"text_search": "C:\\\\Windows"}),
            ("term with space",      {"text_search": "Windows Search Service"}),
        ]
        print("\n  search options, JM vs normal:")
        for _label, _cfg in _opts:
            jm_model.apply_filter(dict(_cfg)); settle(); _a = jm_model.rowCount()
            jm_model.clear_filter(); settle()
            npx.set_advanced_filter(dict(_cfg)); _b = npx.rowCount()
            npx.set_advanced_filter(None)
            print(f"    {_label:<22} jm={_a:>7}  normal={_b:>7}")
            check(f"option '{_label}' agrees across modes", _a == _b,
                  f"jm={_a} normal={_b}")

        # a multi-term list must not crash Normal Mode (it used to raise
        # AttributeError: 'list' object has no attribute 'lower')
        try:
            npx.set_advanced_filter({"text_search": ["a", "b"], "search_mode": "OR"})
            npx.rowCount(); npx.set_advanced_filter(None)
            check("multi-term list does not crash normal mode", True)
        except Exception as _exc:
            check("multi-term list does not crash normal mode", False, repr(_exc))

        # ── the DIALOG must actually emit the text in Juggernaut Mode ────
        # The engine work is worthless if the control is greyed out or the
        # value is clamped on the way out, which is exactly what happened:
        # text search was engine-complete but UI-unreachable in JM.
        from evtx_tool.gui.filter_dialog import FilterDialog
        for _jm in (True, False):
            _d = FilterDialog(metadata={}, current_filter={}, juggernaut_mode=_jm)
            _d._inp_text.setText("svchost")
            _d._chk_regex.setChecked(True)
            _d._chk_text_exclude.setChecked(True)
            _cfg = _d.get_filter_config()
            _lbl = "JM" if _jm else "normal"
            check(f"filter dialog ({_lbl}) leaves the text field usable",
                  _d._inp_text.isEnabled() and _d._chk_regex.isEnabled())
            check(f"filter dialog ({_lbl}) emits the text term unclamped",
                  _cfg.get("text_search") == "svchost"
                  and _cfg.get("text_regex") is True
                  and _cfg.get("text_exclude") is True,
                  f"{_cfg.get('text_search')!r} regex={_cfg.get('text_regex')} "
                  f"excl={_cfg.get('text_exclude')}")

        # and that config must give the same answer through both models
        _d = FilterDialog(metadata={}, current_filter={}, juggernaut_mode=True)
        _d._inp_text.setText("svchost")
        _dcfg = _d.get_filter_config()
        jm_model.apply_filter(dict(_dcfg)); settle(); _a = jm_model.rowCount()
        jm_model.clear_filter(); settle()
        npx.set_advanced_filter(dict(_dcfg)); _b = npx.rowCount()
        npx.set_advanced_filter(None)
        check("dialog-built config agrees across modes", _a == _b,
              f"jm={_a} normal={_b}")

        # a term that is genuinely absent must still return nothing
        a, b = jm("zz-not-present-zz"), norm("zz-not-present-zz")
        check("absent term returns nothing in both modes", a == 0 and b == 0, f"{a}/{b}")
        jm_model._filter_thread.stop()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
