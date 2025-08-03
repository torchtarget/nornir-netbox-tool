# Nornir Network Watch

Nornir Network Watch is a lightweight Python-based network validation tool that uses NetBox as the source of truth to keep your network aligned with the intended state.

## Features

- Discover devices and services automatically from NetBox.
- Validate network state via ping, HTTP(S), TCP, or custom checks.
- Detect drift or failures (e.g., unknown IPs, down services, certificate expiry).
- Send real-time alerts to Pushover or other platforms like Slack or Telegram.
- Scan a network for active hosts using ARP.

Ideal for home labs or production environments that want NetBox-driven monitoring without running a full stack like Prometheus or Zabbix.

## Usage

Install dependencies (includes `scapy` for ARP scanning) and run a simple ping check:

```bash
pip install -r requirements.txt
NETBOX_URL=https://netbox.example.com NETBOX_TOKEN=1234abcd \
    python -m nornir_network_watch.cli ping
```

Run an ARP scan of a network:

```bash
python -m nornir_network_watch.cli arp --network 192.168.1.0/24
```

Discover live hosts that are not present in NetBox:

```bash
NETBOX_URL=https://netbox.example.com NETBOX_TOKEN=1234abcd \
    python -m nornir_network_watch.cli discover
```

Sample output:

```
192.168.1.50: aa:bb:cc:dd:ee:ff
```
