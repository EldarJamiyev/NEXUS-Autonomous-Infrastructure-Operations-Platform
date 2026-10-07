"""Online SQLite backup/restore (demo database). For PostgreSQL use pg_dump/pg_restore (docs/operations).

    python -m nexus.database.backup backup [DEST]
    python -m nexus.database.backup restore SOURCE
"""

from __future__ import annotations

import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from nexus.config import get_settings


def _db_path() -> Path:
    url = get_settings().database_url
    if not url.startswith("sqlite"):
        raise SystemExit("backup.py handles SQLite only; use pg_dump for PostgreSQL")
    return Path(url.split("///", 1)[-1])


def backup(dest: str | None = None) -> Path:
    src = _db_path()
    target = Path(dest) if dest else src.parent / "backups" / f"nexus-{datetime.now(tz=UTC):%Y%m%dT%H%M%SZ}.db"
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(src) as s, sqlite3.connect(target) as d:
        s.backup(d)  # consistent online copy, safe while NEXUS is running
    return target


def restore(source: str) -> Path:
    dst = _db_path()
    with sqlite3.connect(source) as s, sqlite3.connect(dst) as d:
        s.backup(d)
    return dst


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("backup", "restore") or (sys.argv[1] == "restore" and len(sys.argv) < 3):
        raise SystemExit(__doc__)
    path = backup(sys.argv[2] if len(sys.argv) > 2 else None) if sys.argv[1] == "backup" else restore(sys.argv[2])
    print(f"{sys.argv[1]} complete: {path}")
