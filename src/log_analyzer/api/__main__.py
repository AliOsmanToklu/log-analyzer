"""`log-analyzer-api migrate` / `log-analyzer-api serve`."""

import argparse
import logging
import sys
from collections.abc import Sequence

from .db import upgrade
from .settings import Settings


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="log-analyzer-api",
        description="Run the log-analyzer REST API. Configure it with LOG_ANALYZER_DATABASE_URL "
        "and LOG_ANALYZER_MAX_UPLOAD_MB.",
    )
    commands = ap.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="Create or upgrade the database schema, then exit")
    serve = commands.add_parser("serve", help="Migrate the database and start the server")
    serve.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    serve.add_argument("--no-migrate", action="store_true", help="Skip the schema upgrade")
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = Settings.from_env()

    if args.command == "migrate" or not args.no_migrate:
        upgrade(settings.database_url)
    if args.command == "serve":
        import uvicorn

        from .app import create_app

        uvicorn.run(create_app(settings), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
