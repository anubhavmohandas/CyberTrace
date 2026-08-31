"""Shared local-corpus freshness helper for the offline dataset adapters
(ofac.py, exchange_tags.py, ellipticpp.py) whose SQLite index is a cache
built once, offline, from a raw source file a human downloads independently
-- CyberTrace has no live sync with OFAC/GraphSense/Elliptic++. Without this,
an index built from an old download stays queryable forever even after the
operator drops a newer raw source into original/, silently representing
stale sanctions/exchange/dataset intelligence as current.

The fingerprint is each raw source file's size + mtime_ns, not a full
content hash -- the OFAC XML alone is 120MB+, and re-reading the whole file
on every available()/index_available() check to prove nothing changed would
defeat "keep normal indexed queries fast". This is the same fingerprint
make/pip already trust for this exact already-built-are-we-current problem;
an index whose recorded fingerprint no longer matches the source's current
stat is treated as stale, no exceptions -- a false "changed" reading merely
costs a rebuild, while a false "unchanged" reading is exactly the silent
staleness this exists to prevent.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable, Optional

_TABLE = "_freshness"
_KEY = "source_fingerprint"


def source_fingerprint(paths: Iterable[Path]) -> str:
    """Cheap (stat, no read) fingerprint of one or more raw source files,
    sorted by path so argument order never matters. A missing file is a
    legitimate part of the fingerprint (it will differ from that same path
    once the file exists), not an error."""
    parts = []
    for p in sorted(paths):
        try:
            st = p.stat()
            parts.append(f"{p.name}:{st.st_size}:{st.st_mtime_ns}")
        except FileNotFoundError:
            parts.append(f"{p.name}:missing")
    return "|".join(parts)


def stamp(index_path: Path, fingerprint: str) -> None:
    """Record `fingerprint` as the index's current source state. Used both
    at the end of a real build (fresh data, fresh fingerprint) and to
    cheaply adopt an index that predates freshness tracking without paying
    for a full rebuild of data that has not actually changed."""
    conn = sqlite3.connect(index_path)
    try:
        conn.execute(f"CREATE TABLE IF NOT EXISTS {_TABLE} "
                     "(key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(f"INSERT OR REPLACE INTO {_TABLE} (key, value) VALUES (?,?)",
                     (_KEY, fingerprint))
        conn.commit()
    finally:
        conn.close()


def read_fingerprint(index_path: Path) -> Optional[str]:
    """The fingerprint recorded at build/stamp time, or None if the index
    has none yet (built before this tracking existed) -- callers must treat
    None as "freshness unknown", never as "fresh"."""
    conn = sqlite3.connect(f"file:{index_path}?mode=ro", uri=True)
    try:
        row = conn.execute(
            f"SELECT value FROM {_TABLE} WHERE key=?", (_KEY,)).fetchone()
        return row[0] if row else None
    except sqlite3.OperationalError:
        return None  # no _freshness table at all: pre-dates this mechanism
    finally:
        conn.close()


def is_stale(index_path: Path, paths: Iterable[Path]) -> bool:
    """True if `index_path` doesn't exist, carries no recorded fingerprint,
    or its recorded fingerprint no longer matches the raw source's current
    state. The "no recorded fingerprint" case covers an index built before
    this mechanism existed -- it must not silently read as fresh just
    because nothing has changed since is_stale() shipped."""
    if not index_path.exists():
        return True
    recorded = read_fingerprint(index_path)
    if recorded is None:
        return True
    return recorded != source_fingerprint(paths)
