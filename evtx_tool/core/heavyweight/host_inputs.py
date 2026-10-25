"""Host-identity input from a Juggernaut dataset.

Names come from the in-memory Arrow table (computer, source_file and
timestamp_utc are all there); EID 6011 renames need their EventData, which
only the Parquet shards hold, so those few rows are read from the shards.
Produces exactly what ``host_identity.inputs_from_events`` produces for the
same files in Normal mode.
"""
from __future__ import annotations

import json
import os

from evtx_tool.core.host_identity import NameStat, Rename, iso_z, parse_rename


def inputs_from_jm(table, parquet_dir: str) -> "tuple[list[NameStat], list[Rename], int]":
    """(names, renames, unreadable 6011 count) for a loaded JM dataset."""
    import duckdb
    from evtx_tool.core.heavyweight.engine import _MANIFEST_FILENAME

    con = duckdb.connect()
    try:
        con.register("host_names_src", table)
        rows = con.execute(
            "SELECT COALESCE(computer, '') AS c, COALESCE(source_file, '') AS f, "
            "count(*), min(timestamp_utc), max(timestamp_utc) "
            "FROM host_names_src GROUP BY 1, 2"
        ).fetchall()
        names = [NameStat(c, f, int(n), iso_z(lo), iso_z(hi)) for c, f, n, lo, hi in rows]

        renames: list[Rename] = []
        bad = 0
        manifest = os.path.join(parquet_dir, _MANIFEST_FILENAME)
        with open(manifest, "r", encoding="utf-8") as fh:
            shards = json.load(fh)
        if shards:
            src = "[" + ", ".join("'" + p.replace("'", "''") + "'" for p in shards) + "]"
            for ts, sf, rid, ed_json in con.execute(
                f"SELECT timestamp_utc, source_file, record_id, event_data_json "
                f"FROM parquet_scan({src}) "
                f"WHERE event_id = 6011 AND lower(provider) = 'eventlog'"
            ).fetchall():
                try:
                    pair = parse_rename(json.loads(ed_json) if ed_json else None)
                except ValueError:
                    pair = None
                if pair is None:
                    bad += 1
                else:
                    renames.append(Rename(pair[0], pair[1], iso_z(ts), sf or "", int(rid or 0)))
        return names, renames, bad
    finally:
        con.close()
