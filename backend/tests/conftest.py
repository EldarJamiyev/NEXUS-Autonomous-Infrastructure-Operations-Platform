"""Test fixtures: one seeded template database (with engine-generated history), copied per test."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from nexus.config import Settings

BASE = {"background_tasks": False, "step_delay_ms": 0, "log_level": "WARNING", "secret_key": "test-secret", "rate_limit_per_minute": 1000,
        "site_timezone": "Asia/Baku"}


def make_settings(path: Path, **extra: object) -> Settings:
    return Settings(database_url=f"sqlite:///{path}", **{**BASE, **extra})


@pytest.fixture(scope="session")
def template_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from nexus.app import create_context

    path = tmp_path_factory.mktemp("template") / "nexus.db"
    ctx = create_context(make_settings(path))
    ctx.engine.dispose()
    return path


@pytest.fixture
def ctx(template_db: Path, tmp_path: Path):
    from nexus.app import create_context

    dst = tmp_path / "nexus.db"
    shutil.copy(template_db, dst)
    context = create_context(make_settings(dst))
    yield context
    context.engine.dispose()


@pytest.fixture
def client(ctx):
    from fastapi.testclient import TestClient

    from nexus.app import create_app

    app = create_app(ctx.settings, ctx=ctx)
    with TestClient(app) as c:
        yield c


def token(client, user: str = "eldar") -> dict[str, str]:
    r = client.post("/api/auth/demo-login", json={"user_id": user})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def chaos(ctx, scenario: str) -> str:
    from nexus.chaos.scenarios import run_followup, start

    with ctx.session() as db:
        run, sc = start(ctx, db, scenario, actor="pytest")
        run_id, followups = run.id, list(sc.followups)
    for _delay, fn in followups:
        with ctx.session() as db:
            run_followup(ctx, db, run_id, fn)
    return run_id


def process(ctx, rounds: int = 2) -> None:
    from nexus.simulation.history import process as _process

    _process(ctx, rounds=rounds)
