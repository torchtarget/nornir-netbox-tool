"""Command line interface for Nornir Network Watch."""
from __future__ import annotations

import os
import argparse

from .core import NornirNetworkWatch, Settings
from .alerts import send_alert


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run simple checks using NetBox data")
    parser.add_argument(
        "action",
        choices=["ping", "arp", "discover", "https-cert", "http", "tcp"],
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
    parser.add_argument("--http-url", dest="http_url", help="URL to check via HTTP")
    parser.add_argument("--tcp-host", dest="tcp_host", help="Host for TCP check")
    parser.add_argument(
        "--tcp-port", dest="tcp_port", type=int, help="Port for TCP check"
    )
    parser.add_argument(
        "--pushover-token",
        dest="pushover_token",
        help="Pushover API token",
        default=os.getenv("PUSHOVER_TOKEN"),
    )
    parser.add_argument(
        "--pushover-user",
        dest="pushover_user",
        help="Pushover user or group key",
        default=os.getenv("PUSHOVER_USER"),
    )
    parser.add_argument(
        "--slack-webhook",
        dest="slack_webhook",
        help="Slack webhook URL",
        default=os.getenv("SLACK_WEBHOOK"),
    )
    parser.add_argument(
        "--cert-warn-days",
        dest="cert_warn_days",
        type=int,
        help="Days before cert expiry to alert",
        default=int(os.getenv("CERT_WARNING_DAYS", 30)),
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

    settings = Settings(
        netbox_url=args.url,
        netbox_token=args.token,
        pushover_token=args.pushover_token,
        pushover_user=args.pushover_user,
        slack_webhook=args.slack_webhook,
        cert_warning_days=args.cert_warn_days,
    )
    watcher = NornirNetworkWatch(settings)

    if args.action == "ping":
        results = watcher.ping(respect_tags=args.respect_tags)
        for host, task_result in results.items():
            print(f"{host}: {task_result[0].result}")
            if task_result.failed:
                send_alert(
                    f"Ping failed for {host}",
                    settings.pushover_token,
                    settings.pushover_user,
                    settings.slack_webhook,
                )
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
            if task_result.failed or days <= settings.cert_warning_days:
                send_alert(
                    f"Certificate for {args.cert_url} expires in {days} days ({host})",
                    settings.pushover_token,
                    settings.pushover_user,
                    settings.slack_webhook,
                )
    elif args.action == "http":
        if not args.http_url:
            parser.error("--http-url is required for http action")
        results = watcher.http(args.http_url, respect_tags=args.respect_tags)
        for host, task_result in results.items():
            status = task_result[0].result
            print(f"{host}: {status}")
            if task_result.failed or status >= 400:
                send_alert(
                    f"HTTP check failed for {host}: status {status}",
                    settings.pushover_token,
                    settings.pushover_user,
                    settings.slack_webhook,
                )
    elif args.action == "tcp":
        if not args.tcp_host or not args.tcp_port:
            parser.error("--tcp-host and --tcp-port are required for tcp action")
        results = watcher.tcp(
            args.tcp_host, args.tcp_port, respect_tags=args.respect_tags
        )
        for host, task_result in results.items():
            print(f"{host}: {task_result[0].result}")
            if task_result.failed:
                send_alert(
                    f"TCP check failed for {host}:{args.tcp_port} -> {args.tcp_host}",
                    settings.pushover_token,
                    settings.pushover_user,
                    settings.slack_webhook,
                )


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
