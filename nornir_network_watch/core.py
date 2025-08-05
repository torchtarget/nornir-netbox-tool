"""Core functionality for Nornir Network Watch.

This module provides a small wrapper around Nornir and the NetBox
inventory plugin so that network devices can be discovered from NetBox
and simple validation checks can be executed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, List

import os
import requests
from nornir import InitNornir
from nornir.core.plugins.inventory import InventoryPluginRegister
from nornir_netbox.plugins.inventory import NetBoxInventory2 as NetBoxInventory


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
    pushover_token: Optional[str] = os.getenv("PUSHOVER_TOKEN")
    pushover_user: Optional[str] = os.getenv("PUSHOVER_USER")
    slack_webhook: Optional[str] = os.getenv("SLACK_WEBHOOK")
    cert_warning_days: int = int(os.getenv("CERT_WARNING_DAYS", 30))


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

    def _get_services(self, host) -> List[Dict[str, Any]]:
        """Return NetBox services attached to ``host``."""

        headers = {"Authorization": f"Token {self.nb_token}", "Accept": "application/json"}
        device_id = host.data.get("id")
        if device_id is None:
            return []
        url = f"{self.nb_url}/api/ipam/services/?device_id={device_id}&limit=0"
        return requests.get(url, headers=headers).json().get("results", [])

    def ping(self, respect_tags: bool = False) -> Dict[str, Any]:
        """Run ICMP ping against hosts from NetBox.

        If ``respect_tags`` is ``True``, only devices tagged with
        ``scan:ping`` will be pinged.
        """

        tag = self._tag_for("ping")
        nr = self._filter_by_tag(tag) if respect_tags else self.nr
        def _ping(task):
            import subprocess
            try:
                result = subprocess.run(['ping', '-c', '1', task.host.hostname], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            except subprocess.TimeoutExpired:
                return False
            except Exception:
                return False
        return nr.run(_ping)

    def http(
        self,
        url: Optional[str] = None,
        verify: bool = True,
        timeout: int = 5,
        respect_tags: bool = False,
    ) -> Dict[str, Any]:
        """Run HTTP checks derived from NetBox services.

        When ``url`` is provided the behaviour matches the original
        implementation and the same ``url`` is requested from each host. If
        ``url`` is ``None`` then the NetBox ``services`` attached to each host
        are queried and any service named ``http`` or ``https`` is used to
        build the request URL automatically.

        If ``respect_tags`` is ``True``, only devices tagged with
        ``scan:http`` will execute this check.
        """

        def _http(task, url: str) -> int:
            response = requests.get(url, verify=verify, timeout=timeout)
            return response.status_code

        tag = self._tag_for("http")
        nr = self._filter_by_tag(tag) if respect_tags else self.nr

        if url is not None:
            res = nr.run(task=_http, url=url)
            return {host: r[0].result for host, r in res.items()}

        results: Dict[str, Dict[str, int]] = {}
        for host in nr.inventory.hosts.values():
            services = self._get_services(host)
            for svc in services:
                name = (svc.get("name") or "").lower()
                protocol = svc.get("protocol")
                port = svc.get("port")
                if protocol != "tcp" or name not in {"http", "https"}:
                    continue
                scheme = "https" if name == "https" else "http"
                svc_url = f"{scheme}://{host.hostname}:{port}"
                r = nr.filter(name=host.name).run(task=_http, url=svc_url)
                results.setdefault(host.name, {})[svc_url] = r[host.name][0].result
        return results

    def tcp(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: int = 5,
        respect_tags: bool = False,
    ) -> Dict[str, Any]:
        """Attempt to open TCP connections derived from NetBox services.

        Providing ``host`` and ``port`` preserves the original behaviour of
        checking a single endpoint from all hosts. When both are ``None`` the
        services attached to each device in NetBox are queried and every TCP
        service (except those named ``http``/``https`` which are handled by the
        :meth:`http` method) is checked automatically.

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

        if host is not None and port is not None:
            res = nr.run(task=_tcp, host=host, port=port)
            return {h: r[0].result for h, r in res.items()}

        results: Dict[str, Dict[int, bool]] = {}
        for host_obj in nr.inventory.hosts.values():
            services = self._get_services(host_obj)
            for svc in services:
                name = (svc.get("name") or "").lower()
                protocol = svc.get("protocol")
                port_num = svc.get("port")
                if protocol != "tcp" or name in {"http", "https"}:
                    continue
                r = nr.filter(name=host_obj.name).run(
                    task=_tcp, host=host_obj.hostname, port=port_num
                )
                results.setdefault(host_obj.name, {})[port_num] = r[host_obj.name][0].result
        return results

    def check_https_cert(
        self,
        url: Optional[str] = None,
        warn_days: Optional[int] = None,
        timeout: int = 5,
        respect_tags: bool = False,
    ) -> Dict[str, Any]:
        """Check HTTPS certificate expiry using NetBox service data.

        When ``url`` is provided a single HTTPS endpoint is checked from all
        hosts. If ``url`` is ``None`` the device's services are queried and any
        service named ``https`` automatically triggers a certificate check.

        Returns a mapping of host to days remaining. If multiple HTTPS services
        exist on a host, the mapping value is another dictionary keyed by URL.

        If ``respect_tags`` is ``True``, only devices tagged with
        ``scan:https-cert`` will execute this check.
        """

        import logging
        import ssl
        import socket
        from datetime import datetime
        from urllib.parse import urlparse
        from nornir.core.task import Result

        def _https_cert(task, url: str, warn_days: Optional[int]) -> Result:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or 443

            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            not_after = cert["notAfter"]
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (expires - datetime.utcnow()).days
            severity = (
                logging.WARNING
                if warn_days is not None and days_remaining < warn_days
                else logging.INFO
            )
            return Result(host=task.host, result=days_remaining, severity_level=severity)

        tag = self._tag_for("check_https_cert")
        nr = self._filter_by_tag(tag) if respect_tags else self.nr

        if url is not None:
            res = nr.run(task=_https_cert, url=url, warn_days=warn_days)
            return {h: r[0].result for h, r in res.items()}

        results: Dict[str, Dict[str, int]] = {}
        for host_obj in nr.inventory.hosts.values():
            services = self._get_services(host_obj)
            for svc in services:
                name = (svc.get("name") or "").lower()
                protocol = svc.get("protocol")
                port_num = svc.get("port")
                if protocol != "tcp" or name != "https":
                    continue
                svc_url = f"https://{host_obj.hostname}:{port_num}"
                r = nr.filter(name=host_obj.name).run(
                    task=_https_cert, url=svc_url, warn_days=warn_days
                )
                results.setdefault(host_obj.name, {})[svc_url] = r[host_obj.name][0].result
        return results

    def arp_scan(self, network: str) -> Dict[str, str]:
        """Perform an ARP scan and return a mapping of IP to MAC addresses."""
        import subprocess
        import re
        
        print(f"   🔍 Running: nmap -sn {network}")
        
        try:
            # Use nmap with ARP discovery for local networks
            result = subprocess.run(['nmap', '-sn', network], 
                                  capture_output=True, text=True, timeout=120)
            
            print(f"   📡 nmap exit code: {result.returncode}")
            if result.returncode != 0:
                print(f"   ❌ nmap stderr: {result.stderr}")
                return {}
            
            # Debug: show first few lines of nmap output
            lines = result.stdout.split('\n')
            print(f"   📄 First 5 lines of nmap output:")
            for line in lines[:5]:
                if line.strip():
                    print(f"      {line}")
            
            # Parse nmap output for IP/MAC pairs
            devices = {}
            current_ip = None
            
            for line in lines:
                # Look for IP addresses in different formats
                ip_match = re.search(r'Nmap scan report for (?:.*? \()?(\d+\.\d+\.\d+\.\d+)\)?', line)
                if ip_match:
                    current_ip = ip_match.group(1)
                    print(f"   🎯 Found IP: {current_ip}")
                
                # Look for MAC addresses
                if current_ip and 'MAC Address:' in line:
                    mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})', line)
                    if mac_match:
                        mac = mac_match.group(1)
                        devices[current_ip] = mac
                        print(f"   📍 Found MAC for {current_ip}: {mac}")
                        current_ip = None  # Reset for next device
                
                # If we found an IP but no MAC (same subnet), assume it responded to ping
                elif current_ip and ('Host is up' in line or 'Latency' in line):
                    # For devices on same subnet, nmap won't show MAC
                    devices[current_ip] = "Unknown"
                    print(f"   📍 Found responding IP (no MAC): {current_ip}")
                    current_ip = None
            
            print(f"   ✅ Total devices found: {len(devices)}")
            return devices
            
        except subprocess.TimeoutExpired:
            print(f"   ⏰ Timeout scanning {network}")
            return {}
        except FileNotFoundError:
            print(f"   ❌ nmap not found - please install nmap")
            return {}
        except Exception as e:
            print(f"   ❌ Error scanning {network}: {e}")
            return {}

    def discover_unknown_devices(self) -> Dict[str, str]:
        """Scan all prefixes in NetBox and return IP/MAC pairs not present in NetBox."""
        headers = {"Authorization": f"Token {self.nb_token}", "Accept": "application/json"}
        
        print("🌐 Fetching NetBox prefixes...")
        nb_prefixes = requests.get(
            f"{self.nb_url}/api/ipam/prefixes/?limit=0", headers=headers
        ).json()["results"]
        print(f"📋 Found {len(nb_prefixes)} prefixes in NetBox")
        
        print("📱 Fetching known IP addresses from NetBox...")
        nb_ips = requests.get(
            f"{self.nb_url}/api/ipam/ip-addresses/?limit=0", headers=headers
        ).json()["results"]
        known_ips = {ip["address"].split("/")[0] for ip in nb_ips}
        print(f"📝 Found {len(known_ips)} known IP addresses in NetBox")
        
        unknown: Dict[str, str] = {}
        for i, prefix in enumerate(nb_prefixes, 1):
            network = prefix["prefix"]
            print(f"\n🔍 Scanning prefix {i}/{len(nb_prefixes)}: {network}")
            hosts = self.arp_scan(network)
            print(f"   📊 Found {len(hosts)} responding devices in {network}")
            
            known_in_prefix = 0
            unknown_in_prefix = 0
            
            for ip, mac in hosts.items():
                if ip in known_ips:
                    known_in_prefix += 1
                    print(f"   ✅ Known device: {ip} ({mac})")
                else:
                    unknown_in_prefix += 1
                    unknown[ip] = mac
                    print(f"   ❓ UNKNOWN device: {ip} ({mac})")
            
            print(f"   📈 Summary for {network}: {known_in_prefix} known, {unknown_in_prefix} unknown")
        
        # Heavy scan unknown devices 
        if unknown:
            print(f"\n🔬 Starting detailed scan of {len(unknown)} unknown devices...")
            
            # Create output file with timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"unknown_devices_{timestamp}.txt"
            
            with open(output_file, 'w') as f:
                f.write(f"Unknown Devices Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                for ip, mac in unknown.items():
                    scan_result = self.scan_unknown_device(ip, mac)
                    f.write(f"Device: {ip} ({mac})\n")
                    f.write("-" * 40 + "\n")
                    f.write(scan_result)
                    f.write("\n" + "=" * 80 + "\n\n")
            
            print(f"\n📄 Scan results saved to: {output_file}")
        
        return unknown

    def scan_unknown_device(self, ip: str, mac: str) -> str:
        """Perform nmap scan on unknown device and return raw output."""
        import subprocess
        
        print(f"\n🔍 Scanning {ip} ({mac})...")
        
        # NetBox-focused scan: ports, services, OS, hostname
        try:
            print(f"   Running: nmap -sS -sV -O --script=banner,http-title,snmp-info {ip}")
            result = subprocess.run(['nmap', '-sS', '-sV', '-O', '--script=banner,http-title,snmp-info', ip], 
                                  capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print("   📄 nmap output:")
                output_lines = []
                for line in result.stdout.split('\n'):
                    if line.strip():
                        print(f"      {line}")
                        output_lines.append(line)
                return '\n'.join(output_lines)
            else:
                error_msg = f"nmap failed with exit code {result.returncode}"
                if result.stderr:
                    error_msg += f"\nstderr: {result.stderr}"
                print(f"   ❌ {error_msg}")
                return error_msg
                    
        except subprocess.TimeoutExpired:
            error_msg = f"nmap scan timeout for {ip}"
            print(f"   ⏰ {error_msg}")
            return error_msg
        except Exception as e:
            error_msg = f"nmap scan error: {e}"
            print(f"   ❌ {error_msg}")
            return error_msg
