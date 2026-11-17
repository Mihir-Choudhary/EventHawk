"""Formula-safe CSV for Sentinel's own reports, without evtx_tool.

The same rule as every EventHawk CSV (user decision 2026-11-06, see
evtx_tool.output.exporters.csv_cell): a text cell starting with = + - @ TAB
or CR, or with = + - @ after blank characters (ruling R37, 2026-11-17), gets one leading apostrophe; plain numbers and the lone "-" are
untouched.  Sentinel is a standalone package and imported that writer from
evtx_tool, so its CSV report failed outside the EventHawk tree (Gemini audit
10-12).  test_sentinel_csv_standalone checks the two stay the same.
"""
from __future__ import annotations

import csv
import re

_PLAIN_NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
_FORMULA_FIRST = frozenset("=+-@\t\r")


def csv_cell(value):
    if not isinstance(value, str) or not value:
        return value
    if value[0] in _FORMULA_FIRST:
        risky = value
    else:
        # Ruling R37 (2026-11-17, Gemini 6-12): blank characters (str.isspace)
        # before = + - @ do not make a formula safe.
        risky = value.lstrip().rstrip()
        if not risky or risky[0] not in "=+-@":
            return value
    if risky == "-" or _PLAIN_NUMBER.fullmatch(risky):
        return value
    return "'" + value


class SafeDictWriter(csv.DictWriter):
    """csv.DictWriter whose every value goes through csv_cell()."""

    def writerow(self, rowdict):
        return super().writerow({k: csv_cell(v) for k, v in rowdict.items()})

    def writerows(self, rowdicts):
        for r in rowdicts:
            self.writerow(r)
