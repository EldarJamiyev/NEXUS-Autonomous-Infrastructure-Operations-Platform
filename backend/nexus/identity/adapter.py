"""Identity provider interface.

`DirectoryIdentityProvider` reads the identity tables. In simulation those tables are seeded
from simulation/enterprise.yaml (a simulated AD). In a real lab they are filled by
powershell/Get-NexusADInventory.ps1 pushing an inventory to POST /api/ingest/ad-inventory and by
Get-NexusSecurityEvents.ps1 pushing security events - the engines cannot tell the difference,
which is the point: one identity interface, two sources.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, Group, User, UserGroup


class IdentityProvider(ABC):
    name: str
    mode: str

    @abstractmethod
    def groups_for(self, db: Session, user_id: str) -> list[str]: ...

    @abstractmethod
    def user(self, db: Session, user_id: str) -> User | None: ...

    @abstractmethod
    def computer_exists(self, db: Session, hostname: str) -> bool: ...

    def members_of(self, db: Session, group_id: str) -> list[str]:
        return list(db.scalars(select(UserGroup.user_id).where(UserGroup.group_id == group_id)))

    def privileged(self, db: Session, user_id: str) -> bool:
        groups = self.groups_for(db, user_id)
        return any(g.privileged for g in db.scalars(select(Group).where(Group.id.in_(groups))))


class DirectoryIdentityProvider(IdentityProvider):
    def __init__(self, simulated: bool) -> None:
        self.name = "mock-ad" if simulated else "ad-inventory"
        self.mode = "SIMULATION" if simulated else "REAL LAB"

    def groups_for(self, db: Session, user_id: str) -> list[str]:
        return sorted(db.scalars(select(UserGroup.group_id).where(UserGroup.user_id == user_id)))

    def user(self, db: Session, user_id: str) -> User | None:
        return db.get(User, user_id.lower())

    def computer_exists(self, db: Session, hostname: str) -> bool:
        dev = db.get(Device, hostname.upper())
        return bool(dev and dev.ad_computer)
