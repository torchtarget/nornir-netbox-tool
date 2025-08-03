"""Core functionality for Nornir Network Watch.

This module provides a small wrapper around Nornir and the NetBox
inventory plugin so that network devices can be discovered from NetBox
and simple validation checks can be executed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import requests
from nornir import InitNornir
from nornir.core.plugins.inventory import InventoryPluginRegister
from nornir_netbox.plugins.inventory import NetBoxInventory2 as NetBoxInventory
from nornir.plugins.tasks import networking


# Mapping of NetBox tags to the scan methods they enable
SCAN_TAG_MAP = {
    "scan:ping": "ping",
    "scan:http": "http",
    "scan:tcp": "tcp",
    "scan:https-cert": "check_https_cert",
}


@dataclass
class Settings:
    """Configuration options for :class:`NornirNetworkWatch`."""

    netbox_url: str
    netbox_token: str


class NornirNetworkWatch:
    """Lightweight wrapper around Nornir for network validation."""

    def __init__(self, settings: Settings) -> None:
        InventoryPluginRegister.register("NetBoxInventory", NetBoxInventory)
        self.nb_url = settings.netbox_url.rstrip("/")
        self.nb_token = settings.netbox_token
        self.nr = InitNornir(
            inventory={
                "plugin": "NetBoxInventory",
                "options": {
                    "nb_url": self.nb_url,
                    "nb_token": self.nb_token,
                },
            }
        )

    def _filter_by_tag(self, tag: str):
        """Return a Nornir object filtered to hosts with ``tag``.

        The NetBox inventory plugin stores tags as a list of dictionaries
        on each host. Each dictionary contains at minimum the ``slug`` and
        ``name`` of the tag. This helper normalises that structure and
        returns a filtered Nornir object containing only hosts that include
        the given tag.
        """

        def has_tag(host) -> bool:  # pragma: no cover - simple filter
            tags = {t.get("slug") or t.get("name") for t in host.data.get("tags", [])}
            return tag in tags

        return self.nr.filter(filter_func=has_tag)

    def _tag_for(self, method: str) -> str:
        """Return the NetBox tag corresponding to a scan method."""
        for tag, m in SCAN_TAG_MAP.items():
            if m == method:
                return tag
        raise KeyError(method)

    def ping(self, respect_tags: bool = False) -> Dict[str, Any]:
        """Run ICMP ping against hosts from NetBox.

        If ``respect_tags`` is ``True``, only devices tagged with
        ``scan:ping`` will be pinged.
        """

        tag = self._tag_for("ping")
        nr = self._filter_by_tag(tag) if respect_tags else self.nr
        return nr.run(networking.ping)

    def http(
        self,
        url: str,
        verify: bool = True,
        timeout: int = 5,
        respect_tags: bool = False,
    ) -> Dict[str, Any]:
        """Run a simple HTTP GET request from each host.

        If ``respect_tags`` is ``True``, only devices tagged with
        ``scan:http`` will execute this check.
        """

        def _http(task, url: str) -> int:
            response = requests.get(url, verify=verify, timeout=timeout)
            return response.status_code

        tag = self._tag_for("http")
        nr = self._filter_by_tag(tag) if respect_tags else self.nr
        return nr.run(task=_http, url=url)

    def tcp(
        self,
        host: str,
        port: int,
        timeout: int = 5,
        respect_tags: bool = False,
    ) -> Dict[str, Any]:
        """Attempt to open a TCP connection from each host.

        If ``respect_tags`` is ``True``, only devices tagged with
        ``scan:tcp`` will attempt the connection.
        """
        import socket

        def _tcp(task, host: str, port: int) -> bool:
            sock = socket.socket()
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True

        tag = self._tag_for("tcp")
        nr = self._filter_by_tag(tag) if respect_tags else self.nr
        return nr.run(task=_tcp, host=host, port=port)

    def check_https_cert(
        self,
        url: str,
        timeout: int = 5,
        respect_tags: bool = False,
    ) -> Dict[str, Any]:
        """Check HTTPS certificate expiry for a URL.

        Returns the number of days remaining until the certificate expires.

        If ``respect_tags`` is ``True``, only devices tagged with
        ``scan:https-cert`` will execute this check.
        """

        import ssl
        import socket
        from datetime import datetime
        from urllib.parse import urlparse

        def _https_cert(task, url: str) -> int:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or 443

            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            not_after = cert["notAfter"]
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return (expires - datetime.utcnow()).days

        tag = self._tag_for("check_https_cert")
        nr = self._filter_by_tag(tag) if respect_tags else self.nr
        return nr.run(task=_https_cert, url=url)

    def arp_scan(self, network: str) -> Dict[str, str]:
        """Perform an ARP scan and return a mapping of IP to MAC addresses."""
        from scapy.all import arping

        answered, _ = arping(network, verbose=False)
        return {rcv.psrc: rcv.hwsrc for _, rcv in answered}

    def discover_unknown_devices(self) -> Dict[str, str]:
        """Scan all prefixes in NetBox and return IP/MAC pairs not present in NetBox."""
        headers = {"Authorization": f"Token {self.nb_token}", "Accept": "application/json"}
        nb_prefixes = requests.get(
            f"{self.nb_url}/api/ipam/prefixes/?limit=0", headers=headers
        ).json()["results"]
        nb_ips = requests.get(
            f"{self.nb_url}/api/ipam/ip-addresses/?limit=0", headers=headers
        ).json()["results"]
        known_ips = {ip["address"].split("/")[0] for ip in nb_ips}
        unknown: Dict[str, str] = {}
        for prefix in nb_prefixes:
            network = prefix["prefix"]
            hosts = self.arp_scan(network)
            for ip, mac in hosts.items():
                if ip not in known_ips:
                    unknown[ip] = mac
        return unknown
