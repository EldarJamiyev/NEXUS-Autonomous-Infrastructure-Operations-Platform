"""`nexus-server` entry point."""

from __future__ import annotations

import uvicorn

from nexus.config import get_settings


def main() -> None:
    settings = get_settings()
    from nexus.app import create_app

    app = create_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port, log_config=None, proxy_headers=True)


if __name__ == "__main__":
    main()
