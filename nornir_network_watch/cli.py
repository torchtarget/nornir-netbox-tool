"""Command line interface for Nornir Network Watch."""
from __future__ import annotations

import os
import argparse
import logging

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
        "--warn-days",
        dest="warn_days",
        type=int,
        help="Days before cert expiry to warn",
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
        print(f"🏓 Running ping checks (respect_tags={respect_tags})...")
        results = watcher.ping(respect_tags=respect_tags)
        print(f"✅ Ping completed for {len(results)} hosts")
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
        print(f"🔍 Scanning network {network} for devices...")
        results = watcher.arp_scan(network)
        print(f"✅ Found {len(results)} devices")
        for ip, mac in results.items():
            print(f"{ip}: {mac}")
    elif action == "discover":
        print("🔍 Discovering unknown devices...")
        print("📋 Fetching NetBox prefixes and IP addresses...")
        results = watcher.discover_unknown_devices()
        print(f"✅ Found {len(results)} unknown devices")
        if results:
            print("📊 Unknown devices (IP: MAC):")
            for ip, mac in results.items():
                print(f"  {ip}: {mac}")
        else:
            print("🎉 No unknown devices found - all devices are documented in NetBox!")
    elif action == "https-cert":
        cert_url = kwargs.get("cert_url") or kwargs.get("url")
        warn_days = kwargs.get("warn_days", settings.cert_warning_days)
        results = watcher.check_https_cert(
            cert_url, warn_days=warn_days, respect_tags=respect_tags
        )
        if cert_url:
            for host, days in results.items():
                warn = days < warn_days if warn_days is not None else False
                status = "WARNING" if warn else "OK"
                print(f"{host}: {days} days remaining ({status})")
                if warn:
                    send_alert(
                        f"Certificate for {cert_url} expires in {days} days ({host})",
                        settings.pushover_token,
                        settings.pushover_user,
                        settings.slack_webhook,
                    )
        else:
            for host, url_map in results.items():
                for url, days in url_map.items():
                    warn = days < warn_days if warn_days is not None else False
                    status = "WARNING" if warn else "OK"
                    print(f"{host} {url}: {days} days remaining ({status})")
                    if warn:
                        send_alert(
                            f"Certificate for {url} expires in {days} days ({host})",
                            settings.pushover_token,
                            settings.pushover_user,
                            settings.slack_webhook,
                        )
    elif action == "http":
        http_url = kwargs.get("http_url") or kwargs.get("url")
        results = watcher.http(http_url, respect_tags=respect_tags)
        if http_url:
            for host, status in results.items():
                print(f"{host}: {status}")
                if status >= 400:
                    send_alert(
                        f"HTTP check failed for {host}: status {status}",
                        settings.pushover_token,
                        settings.pushover_user,
                        settings.slack_webhook,
                    )
        else:
            for host, url_map in results.items():
                for url, status in url_map.items():
                    print(f"{host} {url}: {status}")
                    if status >= 400:
                        send_alert(
                            f"HTTP check failed for {host}: status {status} ({url})",
                            settings.pushover_token,
                            settings.pushover_user,
                            settings.slack_webhook,
                        )
    elif action == "tcp":
        host = kwargs.get("tcp_host") or kwargs.get("host")
        port = kwargs.get("tcp_port") or kwargs.get("port")
        results = watcher.tcp(
            host, port if port is None else int(port), respect_tags=respect_tags
        )
        if host and port:
            for host_name, ok in results.items():
                print(f"{host_name}: {ok}")
                if not ok:
                    send_alert(
                        f"TCP check failed for {host_name}:{port} -> {host}",
                        settings.pushover_token,
                        settings.pushover_user,
                        settings.slack_webhook,
                    )
        else:
            for host_name, port_map in results.items():
                for port_num, ok in port_map.items():
                    print(f"{host_name}:{port_num}: {ok}")
                    if not ok:
                        send_alert(
                            f"TCP check failed for {host_name}:{port_num}",
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
        print(f"📄 Loading configuration from {args.config}")
        cfg = load_config(args.config)
        print(f"🔗 Connecting to NetBox at {cfg.settings.netbox_url}")
        watcher = NornirNetworkWatch(cfg.settings)
        print(f"🚀 Running {len(cfg.checks)} checks...")
        for i, check in enumerate(cfg.checks, 1):
            print(f"\n--- Check {i}/{len(cfg.checks)}: {check.action} ---")
            run_check(check.action, watcher, cfg.settings, **check.options)
        print(f"\n✅ All checks completed!")
        return

    if not args.action:
        parser.error("action or --config is required")

    settings = Settings(
        netbox_url=args.url,
        netbox_token=args.token,
        pushover_token=args.pushover_token,
        pushover_user=args.pushover_user,
        slack_webhook=args.slack_webhook,
        cert_warning_days=args.warn_days,
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
        warn_days=args.warn_days,
        respect_tags=args.respect_tags,
    )


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
