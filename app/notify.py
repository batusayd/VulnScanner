"""Notifications after a scan: Telegram, Slack/Discord-style webhook and e-mail.

Configure with environment variables (any subset):
  TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
  WEBHOOK_URL            (Slack incoming webhook or any endpoint accepting {"text": "..."})
  SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TO
"""
from __future__ import annotations

import asyncio
import os
import smtplib
from email.message import EmailMessage

import httpx


def configured_channels() -> list[str]:
    ch = []
    if os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
        ch.append("telegram")
    if os.environ.get("WEBHOOK_URL"):
        ch.append("webhook")
    if os.environ.get("SMTP_HOST") and os.environ.get("SMTP_TO"):
        ch.append("email")
    return ch


def build_message(d: dict) -> str:
    s = d["summary"]
    diff = d.get("diff") or {}
    lines = [f"VulnScanner: {d['target']}",
             f"Grade {d.get('grade')} (score {d.get('score')}) - High {s['High']}, "
             f"Medium {s['Medium']}, Low {s['Low']}, Info {s['Info']}"]
    if diff:
        lines.append(f"Since last scan: {len(diff['new'])} new, {len(diff['fixed'])} fixed, "
                     f"{len(diff['persisting'])} unchanged")
        lines += [f"  NEW [{f['severity']}] {f['title']}" for f in diff["new"][:8]]
    return "\n".join(lines)


def _send_email(text: str, subject: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["To"] = subject, os.environ["SMTP_TO"]
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "vulnscanner@localhost"))
    msg.set_content(text)
    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587")), timeout=15) as s:
        s.starttls()
        if os.environ.get("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
        s.send_message(msg)


async def notify(d: dict) -> list[str]:
    """Send the scan summary to every configured channel; failures are logged, never raised."""
    text, sent = build_message(d), []
    async with httpx.AsyncClient(timeout=10) as c:
        try:
            if "telegram" in configured_channels():
                await c.post(f"https://api.telegram.org/bot{os.environ['TELEGRAM_BOT_TOKEN']}/sendMessage",
                             data={"chat_id": os.environ["TELEGRAM_CHAT_ID"], "text": text})
                sent.append("telegram")
            if "webhook" in configured_channels():
                await c.post(os.environ["WEBHOOK_URL"], json={"text": text})
                sent.append("webhook")
        except httpx.HTTPError:
            pass
    try:
        if "email" in configured_channels():
            await asyncio.to_thread(_send_email, text, f"Scan result: {d['target']} ({d.get('grade')})")
            sent.append("email")
    except Exception:  # noqa: BLE001
        pass
    return sent
