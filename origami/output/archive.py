"""Recover stored reports without opening scanner memory for writing."""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from pathlib import Path

from origami.core.files import new_private_stream


def export_saved_report(database: Path, run_id: int, destination: Path) -> None:
    if run_id < 1:
        raise ValueError("run ID must be positive")
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                            "AND name='report_snapshots'").fetchone()
        if not exists:
            raise ValueError("legacy database has no complete report snapshots")
        row = db.execute("SELECT report_json FROM report_snapshots WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise ValueError("no complete snapshot for this run")
    # Exclusive creation prevents overwriting the DB or an existing report,
    # including symlinks and hard-link aliases. Failed writes leave no partial file.
    with new_private_stream(destination) as stream:
        try:
            stream.write(row[0])
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
