"""Persistent runtime settings (autonomy level, maintenance mode, change windows)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from nexus.models import Setting

DEFAULTS: dict[str, Any] = {
    "autonomy_level": 3,
    "maintenance": {"active": False, "reason": "", "started_at": None, "started_by": None, "expected": []},
    "change_windows": [{"name": "Weekly maintenance window", "days": ["sat"], "start": "02:00", "end": "04:00"}],
    "system_mode": {"mode": "NORMAL", "since": None, "reasons": []},
    "demo_report_id": None,
}


def get_setting(db: Session, key: str) -> Any:
    row = db.get(Setting, key)
    if row is None:
        value = DEFAULTS.get(key)
        return dict(value) if isinstance(value, dict) else (list(value) if isinstance(value, list) else value)
    return row.value


def set_setting(db: Session, key: str, value: Any, now: Any = None) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value, updated_at=now))
    else:
        row.value = value
        row.updated_at = now
    db.flush()
