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

Check the remaining validity of an HTTPS certificate and warn when it is
approaching expiry:

```bash
NETBOX_URL=https://netbox.example.com NETBOX_TOKEN=1234abcd \
    python -m nornir_network_watch.cli https-cert --cert-url https://example.com --warn-days 45
```

Sample output:

```
localhost: 10 days remaining (WARNING)
```

## Tag-based scans

Devices in NetBox can be tagged to control which checks run against them.
Tags with the prefix `scan:` enable individual scan types. Supported tags
include:

- `scan:ping` – run ICMP ping checks
- `scan:http` – perform HTTP GET requests
- `scan:tcp` – attempt TCP connections
- `scan:https-cert` – check HTTPS certificate expiry

Use the `--respect-tags` flag with the CLI to limit execution to devices that
carry the corresponding tag:

```bash
NETBOX_URL=https://netbox.example.com NETBOX_TOKEN=1234abcd \
    python -m nornir_network_watch.cli ping --respect-tags
```

Only hosts tagged with `scan:ping` will be included in the run. Without the
flag all devices from NetBox are scanned.

## Configuration file

Multiple checks can be executed sequentially by defining them in a YAML
configuration file and passing it to the CLI with ``--config``:

```bash
python -m nornir_network_watch.cli --config config.yaml
```

The file contains optional global ``settings`` and a list of ``checks``. Any
settings not provided fall back to environment variables or CLI arguments. An
example configuration:

```yaml
settings:
  url: https://netbox.example.com
  token: 1234abcd

checks:
  - action: ping
    respect_tags: true
  - action: https-cert
    url: https://example.com
  - action: tcp
    host: 10.0.0.1
    port: 22
```

Each check entry requires an ``action`` and may include any parameters for that
action such as ``url`` for HTTP/HTTPS checks or ``host``/``port`` for TCP.
