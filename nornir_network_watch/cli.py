"""Command line interface for Nornir Network Watch."""
from __future__ import annotations

import os
import argparse

from .core import NornirNetworkWatch, Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run simple checks using NetBox data")
    parser.add_argument("action", choices=["ping", "arp"], help="Check to run")
    parser.add_argument("--url", dest="url", help="NetBox URL", default=os.getenv("NETBOX_URL"))
    parser.add_argument("--token", dest="token", help="NetBox token", default=os.getenv("NETBOX_TOKEN"))
    parser.add_argument(
        "--network",
        dest="network",
        help="Network to ARP scan (e.g., 192.168.1.0/24)",
    )
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
    elif args.action == "arp":
        if not args.network:
            parser.error("--network is required for arp action")
        results = watcher.arp_scan(args.network)
        for ip, mac in results.items():
            print(f"{ip}: {mac}")


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
