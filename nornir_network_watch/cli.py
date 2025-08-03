"""Command line interface for Nornir Network Watch."""
from __future__ import annotations

import os
import argparse

from .core import NornirNetworkWatch, Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run simple checks using NetBox data")
    parser.add_argument("action", choices=["ping"], help="Check to run")
    parser.add_argument("--url", dest="url", help="NetBox URL", default=os.getenv("NETBOX_URL"))
    parser.add_argument("--token", dest="token", help="NetBox token", default=os.getenv("NETBOX_TOKEN"))
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    settings = Settings(netbox_url=args.url, netbox_token=args.token)
    watcher = NornirNetworkWatch(settings)

    if args.action == "ping":
        results = watcher.ping()
        for host, task_result in results.items():
            print(f"{host}: {task_result[0].result}")


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
