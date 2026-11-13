"""Connector interface. v0.1 ships NO network transport.

`PublicApiConnector` is a documented-public-API stub that is OFF unless PATIENCE_INTEL_CONNECTORS_LIVE=1
AND a transport callable is injected (tests inject a fake; there is no default real transport). It
performs GET requests only to https hosts in PATIENCE_INTEL_API_HOSTS, never follows logins, paywalls or
HTML, and returns the response text for the normal ingest pipeline (which validates everything). It
does not check robots.txt, honour rate limits or send an identifying User-Agent: those are required before
any real connector exists (plan phase H).
"""
from __future__ import annotations
import os
from typing import Callable, Optional, Protocol
from urllib.parse import urlsplit

from .sources import api_hosts


class ConnectorDisabled(Exception):
    pass


class Connector(Protocol):
    def fetch(self, source: dict) -> tuple:
        """Return (format, text) for ingest. Raises ConnectorDisabled when not permitted."""


def live_enabled() -> bool:
    return os.environ.get("PATIENCE_INTEL_CONNECTORS_LIVE", "") == "1"


class PublicApiConnector:
    def __init__(self, transport: Optional[Callable[[str], tuple]] = None, max_bytes: int = 2_000_000):
        self.transport, self.max_bytes = transport, max_bytes

    def fetch(self, source: dict) -> tuple:
        if not live_enabled():
            raise ConnectorDisabled("live connectors are off (PATIENCE_INTEL_CONNECTORS_LIVE is not 1)")
        if self.transport is None:
            raise ConnectorDisabled("no transport configured: v0.1 ships no network transport")
        if source.get("kind") != "public_api":
            raise ConnectorDisabled("not a public_api source")
        u = urlsplit(source.get("uri") or "")
        if u.scheme != "https" or (u.hostname or "").lower() not in api_hosts():
            raise ConnectorDisabled("host is not allowlisted")
        fmt, text = self.transport(source["uri"])
        if fmt not in ("csv", "json") or not isinstance(text, str) or len(text.encode("utf-8")) > self.max_bytes:
            raise ConnectorDisabled("unsupported or oversized response")
        return fmt, text
