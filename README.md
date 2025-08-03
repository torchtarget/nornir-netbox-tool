# Nornir Network Watch

Nornir Network Watch is a lightweight Python-based network validation tool that uses NetBox as the source of truth to keep your network aligned with the intended state.

## Features

- Discover devices and services automatically from NetBox.
- Validate network state via ping, HTTP(S), TCP, or custom checks.
- Detect drift or failures (e.g., unknown IPs, down services, certificate expiry).
- Send real-time alerts to Pushover or other platforms like Slack or Telegram.

Ideal for home labs or production environments that want NetBox-driven monitoring without running a full stack like Prometheus or Zabbix.

## Usage

Install dependencies and run a simple ping check:

```bash
pip install -r requirements.txt
NETBOX_URL=https://netbox.example.com NETBOX_TOKEN=1234abcd \
    python -m nornir_network_watch.cli ping
```
