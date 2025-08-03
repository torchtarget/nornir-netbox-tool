"""Command line interface for Nornir Network Watch."""
from __future__ import annotations

import os
import argparse

from .core import NornirNetworkWatch, Settings
from .alerts import send_alert
from .config import load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run simple checks using NetBox data")
    parser.add_argument(
        "action",
        nargs="?",
        choices=["ping", "arp", "discover", "https-cert", "http", "tcp"],
        help="Check to run",
    )
    parser.add_argument(
        "--config",
        dest="config",
        help="Path to YAML configuration file defining checks",
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


def run_check(action: str, watcher: NornirNetworkWatch, settings: Settings, **kwargs) -> None:
    """Execute a single check ``action`` with ``watcher``.

    Parameters are passed via ``kwargs`` and mirror the CLI options for each
    action.  Alerts are sent for failed checks using the provided ``settings``.
    """

    respect_tags = kwargs.get("respect_tags", False)
    if action == "ping":
        results = watcher.ping(respect_tags=respect_tags)
        for host, task_result in results.items():
            print(f"{host}: {task_result[0].result}")
            if task_result.failed:
                send_alert(
                    f"Ping failed for {host}",
                    settings.pushover_token,
                    settings.pushover_user,
                    settings.slack_webhook,
                )
    elif action == "arp":
        network = kwargs.get("network")
        if not network:
            raise ValueError("network is required for arp action")
        results = watcher.arp_scan(network)
        for ip, mac in results.items():
            print(f"{ip}: {mac}")
    elif action == "discover":
        results = watcher.discover_unknown_devices()
        for ip, mac in results.items():
            print(f"{ip}: {mac}")
    elif action == "https-cert":
        cert_url = kwargs.get("cert_url") or kwargs.get("url")
        if not cert_url:
            raise ValueError("cert_url is required for https-cert action")
        results = watcher.check_https_cert(cert_url, respect_tags=respect_tags)
        for host, task_result in results.items():
            days = task_result[0].result
            print(f"{host}: {days} days remaining")
            if task_result.failed or days <= settings.cert_warning_days:
                send_alert(
                    f"Certificate for {cert_url} expires in {days} days ({host})",
                    settings.pushover_token,
                    settings.pushover_user,
                    settings.slack_webhook,
                )
    elif action == "http":
        http_url = kwargs.get("http_url") or kwargs.get("url")
        if not http_url:
            raise ValueError("http_url is required for http action")
        results = watcher.http(http_url, respect_tags=respect_tags)
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
    elif action == "tcp":
        host = kwargs.get("tcp_host") or kwargs.get("host")
        port = kwargs.get("tcp_port") or kwargs.get("port")
        if not host or not port:
            raise ValueError("tcp_host and tcp_port are required for tcp action")
        results = watcher.tcp(host, int(port), respect_tags=respect_tags)
        for host_name, task_result in results.items():
            print(f"{host_name}: {task_result[0].result}")
            if task_result.failed:
                send_alert(
                    f"TCP check failed for {host_name}:{port} -> {host}",
                    settings.pushover_token,
                    settings.pushover_user,
                    settings.slack_webhook,
                )
    else:  # pragma: no cover - defensive programming
        raise ValueError(f"Unknown action: {action}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.config:
        cfg = load_config(args.config)
        watcher = NornirNetworkWatch(cfg.settings)
        for check in cfg.checks:
            run_check(check.action, watcher, cfg.settings, **check.options)
        return

    if not args.action:
        parser.error("action or --config is required")

    settings = Settings(
        netbox_url=args.url,
        netbox_token=args.token,
        pushover_token=args.pushover_token,
        pushover_user=args.pushover_user,
        slack_webhook=args.slack_webhook,
        cert_warning_days=args.cert_warn_days,
    )
    watcher = NornirNetworkWatch(settings)

    run_check(
        args.action,
        watcher,
        settings,
        network=args.network,
        cert_url=args.cert_url,
        http_url=args.http_url,
        tcp_host=args.tcp_host,
        tcp_port=args.tcp_port,
        respect_tags=args.respect_tags,
    )


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
