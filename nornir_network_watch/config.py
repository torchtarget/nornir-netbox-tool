from __future__ import annotations

"""Configuration loading for Nornir Network Watch.

This module provides helpers to load YAML configuration files which define
how :mod:`nornir_network_watch` should run.  A configuration file contains two
sections:

``settings``
    Connection details and alerting options.  Any values not supplied will
    fall back to environment variables in the same way as the CLI options.

``checks``
    A list of check definitions.  Each entry requires an ``action`` key and
    may include any options for that action, such as ``url`` for HTTP checks
    or ``host``/``port`` for TCP checks.
"""

from dataclasses import dataclass
from typing import Any, Dict, List
import os

import yaml

from .core import Settings


@dataclass
class Check:
    """Single check definition parsed from the configuration file."""

    action: str
    options: Dict[str, Any]


@dataclass
class Config:
    """Full configuration consisting of global settings and checks."""

    settings: Settings
    checks: List[Check]


def load_config(path: str) -> Config:
    """Load configuration from ``path``.

    Parameters
    ----------
    path:
        Path to a YAML file containing configuration data.
    """

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    settings_data = data.get("settings", {})
    settings = Settings(
        netbox_url=settings_data.get("url") or os.getenv("NETBOX_URL"),
        netbox_token=settings_data.get("token") or os.getenv("NETBOX_TOKEN"),
        pushover_token=settings_data.get("pushover_token")
        or os.getenv("PUSHOVER_TOKEN"),
        pushover_user=settings_data.get("pushover_user")
        or os.getenv("PUSHOVER_USER"),
        slack_webhook=settings_data.get("slack_webhook")
        or os.getenv("SLACK_WEBHOOK"),
        cert_warning_days=int(
            settings_data.get("cert_warning_days")
            or os.getenv("CERT_WARNING_DAYS", 30)
        ),
    )

    checks: List[Check] = []
    for raw_check in data.get("checks", []):
        action = raw_check.get("action")
        if not action:
            raise ValueError("Each check requires an 'action' key")
        options = {k: v for k, v in raw_check.items() if k != "action"}
        checks.append(Check(action=action, options=options))

    return Config(settings=settings, checks=checks)
