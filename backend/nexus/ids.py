"""Human-readable sequential identifiers (INC-0001, TX-009183, LEASE-99183, CORR-81983)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from nexus.models import Counter

SEQUENCES: dict[str, tuple[str, int, int]] = {
    "incident": ("INC", 4, 0),
    "tx": ("TX", 6, 9100),
    "drift": ("DRIFT", 3, 0),
    "alert": ("ALR", 4, 0),
    "approval": ("APR", 4, 0),
    "change": ("CHG", 4, 0),
    "corr": ("CORR", 5, 81900),
    "lease": ("LEASE", 5, 99177),
    "decision": ("DEC", 4, 0),
    "chaos": ("CHAOS", 4, 0),
    "report": ("RPT", 4, 0),
    "fwrule": ("FW", 4, 5000),
    "unknown": ("UNKNOWN", 3, 0),
}


def new_id(db: Session, kind: str) -> str:
    prefix, width, start = SEQUENCES[kind]
    row = db.get(Counter, kind)
    if row is None:
        row = Counter(name=kind, value=start)
        db.add(row)
    row.value += 1
    db.flush()
    return f"{prefix}-{row.value:0{width}d}"
