"""Windows Security event normalization (4624, 4625, 4634, 4647, 4672, 4720, 4726, 4728, 4729, 4732, 4733).

Real lab: powershell/Get-NexusSecurityEvents.ps1 posts events to /api/ingest/windows-events.
Simulation: the World emits the same raw shape. Both go through `ingest_windows_event`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, Group, IpAddress, User, UserGroup
from nexus.models import Session as UserSession

if TYPE_CHECKING:
    from nexus.core.context import Context

EVENT_MAP = {4624: "USER_LOGIN", 4625: "AUTH_FAILURE", 4634: "USER_LOGOUT", 4647: "USER_LOGOUT", 4672: "PRIVILEGED_LOGON",
             4720: "ACCOUNT_CREATED", 4726: "ACCOUNT_DELETED", 4728: "GROUP_MEMBER_ADDED", 4729: "GROUP_MEMBER_REMOVED",
             4732: "GROUP_MEMBER_ADDED", 4733: "GROUP_MEMBER_REMOVED"}
FAILURE_REASONS = {"0xC000006A": "bad password", "0xC0000064": "unknown user", "0xC0000234": "account locked out",
                   "0xC000005E": "no logon servers available", "0xC0000072": "account disabled", "0xC000006F": "outside logon hours"}
SUPPORTED_EVENT_IDS = sorted(EVENT_MAP)


def _user_id(raw: Any) -> str:
    name = str(raw or "").split("\\")[-1].split("@")[0]
    return name.lower()


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    event_id = int(raw.get("EventID") or raw.get("Id") or 0)
    if event_id not in EVENT_MAP:
        raise ValueError(f"unsupported Windows event id {event_id}")
    workstation = str(raw.get("WorkstationName") or raw.get("Workstation") or "").upper() or None
    return {
        "event_id": event_id, "type": EVENT_MAP[event_id], "user": _user_id(raw.get("TargetUserName") or raw.get("SubjectUserName")),
        "device": workstation, "ip": raw.get("IpAddress") if raw.get("IpAddress") not in ("-", "::1", "127.0.0.1") else None,
        "logon_type": raw.get("LogonType"), "status": raw.get("SubStatus") or raw.get("Status"),
        "group": str(raw.get("TargetUserName") if event_id in (4728, 4729, 4732, 4733) else raw.get("GroupName") or ""),
        "member": _user_id(raw.get("MemberName")) if raw.get("MemberName") else None, "computer": raw.get("Computer"),
    }


def ingest_windows_event(ctx: Context, db: Session, raw: dict[str, Any], source: str = "powershell") -> dict[str, Any]:
    ev = normalize(raw)
    now = ctx.clock.now()
    src = f"windows-security/{ev['computer'] or 'DC01'}" + (" (simulated)" if source == "simulation" else "")
    user = db.get(User, ev["user"]) if ev["user"] else None
    kind = ev["type"]
    if kind == "USER_LOGIN" and user and ev["device"]:
        existing = db.scalar(select(UserSession).where(UserSession.user_id == user.id, UserSession.device_id == ev["device"],
                                                       UserSession.active.is_(True)))
        if existing is None:
            ip = ev["ip"] or db.scalar(select(IpAddress.address).where(IpAddress.device_id == ev["device"]))
            db.add(UserSession(user_id=user.id, device_id=ev["device"], source_ip=ip, started_at=now, active=True,
                               logon_type=str(ev["logon_type"] or "Interactive"), source=f"event-{ev['event_id']}"))
            db.flush()
        ctx.bus.emit(db, "USER_LOGIN", f"{user.display_name} logged on to {ev['device']} (4624)", source=src,
                     target=ev["device"], user_id=user.id, data=ev)
        _refresh_device(ctx, db, ev["device"], f"session opened by {user.id}")
    elif kind == "USER_LOGOUT" and user and ev["device"]:
        for s in db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.device_id == ev["device"],
                                                      UserSession.active.is_(True))):
            s.active = False
            s.ended_at = now
        ctx.bus.emit(db, "USER_LOGOUT", f"{user.display_name} logged off {ev['device']} ({ev['event_id']})", source=src,
                     target=ev["device"], user_id=user.id, data=ev)
        from nexus.leases.engine import revoke_for_session_end

        revoke_for_session_end(ctx, db, user.id, ev["device"])
        _refresh_device(ctx, db, ev["device"], f"session closed by {user.id}")
    elif kind == "AUTH_FAILURE":
        reason = FAILURE_REASONS.get(str(ev["status"]), str(ev["status"]))
        ctx.bus.emit(db, "AUTH_FAILURE", f"Logon failure for {ev['user'] or 'unknown'} from {ev['device'] or ev['ip'] or '?'}: {reason}",
                     severity="warning", source=src, target=ev["device"], user_id=ev["user"] or None, data={**ev, "reason": reason})
    elif kind in ("GROUP_MEMBER_ADDED", "GROUP_MEMBER_REMOVED") and ev["member"]:
        group = db.get(Group, ev["group"])
        member = db.get(User, ev["member"])
        if group and member:
            link = db.get(UserGroup, (member.id, group.id))
            if kind == "GROUP_MEMBER_ADDED" and link is None:
                db.add(UserGroup(user_id=member.id, group_id=group.id))
            elif kind == "GROUP_MEMBER_REMOVED" and link is not None:
                db.delete(link)
            db.flush()
        ctx.bus.emit(db, kind, f"{ev['member']} {'added to' if kind.endswith('ADDED') else 'removed from'} {ev['group']} ({ev['event_id']})",
                     severity="notice", source=src, user_id=ev["member"], data=ev)
    else:
        ctx.bus.emit(db, kind, f"{kind.replace('_', ' ').title()} for {ev['user']} ({ev['event_id']})", source=src,
                     target=ev["device"], user_id=ev["user"] or None, data=ev, severity="notice")
    return ev


def _refresh_device(ctx: Context, db: Session, device_id: str, reason: str) -> None:
    from nexus.identity.confidence import update_identity
    from nexus.risk.engine import recompute_device

    dev = db.get(Device, device_id)
    if dev:
        update_identity(ctx, db, dev, reason)
        recompute_device(ctx, db, dev, reason)
