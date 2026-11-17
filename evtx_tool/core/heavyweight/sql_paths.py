"""File paths as DuckDB SQL text.

DuckDB's parquet_scan() takes its file list as SQL text, not as a bound
parameter. A path is a SQL string literal: single quotes, with every quote
inside doubled. Pasting a path without that, or pasting a Python list's text
(repr switches to double quotes, which DuckDB reads as an identifier, when a
path contains an apostrophe), breaks the query for anyone whose %TEMP% has an
apostrophe in it, e.g. C:\\Users\\O'Brien (Gemini audit 13-01).
"""
from __future__ import annotations

from typing import Iterable


def sql_str(text: str) -> str:
    """*text* as one SQL string literal."""
    return "'" + str(text).replace("'", "''") + "'"


def sql_path_list(paths: Iterable[str]) -> str:
    """A DuckDB list literal of file paths, for parquet_scan(...)."""
    return "[" + ", ".join(sql_str(p) for p in paths) + "]"
