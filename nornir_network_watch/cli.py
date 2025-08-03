"""Command line interface for Nornir Network Watch."""
from __future__ import annotations

import os
import argparse

from .core import NornirNetworkWatch, Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run simple checks using NetBox data")
    parser.add_argument(
        "action",
        choices=["ping", "arp", "discover", "https-cert"],
        help="Check to run",
    )
    parser.add_argument("--url", dest="url", help="NetBox URL", default=os.getenv("NETBOX_URL"))
    parser.add_argument("--token", dest="token", help="NetBox token", default=os.getenv("NETBOX_TOKEN"))
    parser.add_argument(
        "--network",
        dest="network",
        help="Network to ARP scan (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--cert-url",
        dest="cert_url",
        help="URL to check for HTTPS certificate expiry",
    )
    parser.add_argument(
        "--respect-tags",
        action="store_true",
        dest="respect_tags",
        help="Only run scans on devices with matching 'scan:<action>' tags",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    settings = Settings(netbox_url=args.url, netbox_token=args.token)
    watcher = NornirNetworkWatch(settings)

    if args.action == "ping":
        results = watcher.ping(respect_tags=args.respect_tags)
        for host, task_result in results.items():
            print(f"{host}: {task_result[0].result}")
    elif args.action == "arp":
        if not args.network:
            parser.error("--network is required for arp action")
        results = watcher.arp_scan(args.network)
        for ip, mac in results.items():
            print(f"{ip}: {mac}")
    elif args.action == "discover":
        results = watcher.discover_unknown_devices()
        for ip, mac in results.items():
            print(f"{ip}: {mac}")
    elif args.action == "https-cert":
        if not args.cert_url:
            parser.error("--cert-url is required for https-cert action")
        results = watcher.check_https_cert(args.cert_url, respect_tags=args.respect_tags)
        for host, task_result in results.items():
            days = task_result[0].result
            print(f"{host}: {days} days remaining")


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
