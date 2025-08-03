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


@dataclass
class Settings:
    """Configuration options for :class:`NornirNetworkWatch`."""

    netbox_url: str
    netbox_token: str


class NornirNetworkWatch:
    """Lightweight wrapper around Nornir for network validation."""

    def __init__(self, settings: Settings) -> None:
        InventoryPluginRegister.register("NetBoxInventory", NetBoxInventory)
        self.nr = InitNornir(
            inventory={
                "plugin": "NetBoxInventory",
                "options": {
                    "nb_url": settings.netbox_url,
                    "nb_token": settings.netbox_token,
                },
            }
        )

    def ping(self) -> Dict[str, Any]:
        """Run ICMP ping against all hosts from NetBox."""
        return self.nr.run(networking.ping)

    def http(self, url: str, verify: bool = True, timeout: int = 5) -> Dict[str, Any]:
        """Run a simple HTTP GET request from each host."""

        def _http(task, url: str) -> int:
            response = requests.get(url, verify=verify, timeout=timeout)
            return response.status_code

        return self.nr.run(task=_http, url=url)

    def tcp(self, host: str, port: int, timeout: int = 5) -> Dict[str, Any]:
        """Attempt to open a TCP connection from each host."""
        import socket

        def _tcp(task, host: str, port: int) -> bool:
            sock = socket.socket()
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True

        return self.nr.run(task=_tcp, host=host, port=port)

    def arp_scan(self, network: str) -> Dict[str, str]:
        """Perform an ARP scan and return a mapping of IP to MAC addresses."""
        from scapy.all import arping

        answered, _ = arping(network, verbose=False)
        return {rcv.psrc: rcv.hwsrc for _, rcv in answered}
