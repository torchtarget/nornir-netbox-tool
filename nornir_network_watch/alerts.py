"""Alerting helpers for Nornir Network Watch."""
from __future__ import annotations

from typing import Optional

import requests


def send_pushover(message: str, token: str, user: str) -> None:
    """Send ``message`` via Pushover."""
    payload = {"token": token, "user": user, "message": message}
    requests.post("https://api.pushover.net/1/messages.json", data=payload, timeout=5)


def send_slack(message: str, webhook_url: str) -> None:
    """Send ``message`` to a Slack webhook."""
    requests.post(webhook_url, json={"text": message}, timeout=5)


def send_alert(
    message: str,
    pushover_token: Optional[str] = None,
    pushover_user: Optional[str] = None,
    slack_webhook: Optional[str] = None,
) -> None:
    """Send an alert to any configured backends."""
    if pushover_token and pushover_user:
        send_pushover(message, pushover_token, pushover_user)
    if slack_webhook:
        send_slack(message, slack_webhook)
