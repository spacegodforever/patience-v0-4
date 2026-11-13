"""Connector interface. v0.1 ships NO network transport.

`PublicApiConnector` is a documented-public-API stub that is OFF unless PATIENCE_INTEL_CONNECTORS_LIVE=1
AND a transport callable is injected (tests inject a fake; there is no default real transport). It
performs GET requests only to https hosts in PATIENCE_INTEL_API_HOSTS, never follows logins, paywalls or
HTML, and returns the response text for the normal ingest pipeline (which validates everything). It
does not check robots.txt, honour rate limits or send an identifying User-Agent; that stub is unchanged and
still has no real transport.

The guarded-GET framework below (HttpResponse, RateLimiter, validate_user_agent, guarded_get) is what a real
connector (see sec_edgar.py) must go through: https only, exact host allowlist, path allowlist, no userinfo or
odd ports, every redirect hop re-validated, per-request timeout, hard response-size cap, content-encoding
refused, global rate limit with a hard ceiling, and a declared User-Agent with a contact. It performs no I/O
itself: the transport is injected (tests inject fixtures; https_transport.py is the only module that touches
the network).
"""
from __future__ import annotations
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence
from urllib.parse import urljoin, urlsplit

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


# ---------------------------------------------------------------------------- guarded GET framework
class FetchRefused(Exception):
    """A request or response was refused by policy. `code` is a short stable reason for the audit log."""
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code, self.message = code, message or code


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict = field(default_factory=dict)   # lower-case header names
    body: bytes = b""


MAX_RATE_PER_S = 10.0   # SEC's published ceiling; a hard limit in code, not a default
_UA_RE = re.compile(r"^[\x20-\x7e]{10,200}$")
_CONTACT_RE = re.compile(r"([^@\s<>]+@[^@\s<>]+\.[A-Za-z]{2,})|(https?://[^\s]+)")
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def validate_user_agent(ua: Optional[str]) -> str:
    """A declared User-Agent with a contact (email or URL). No default: unset or malformed fails closed."""
    if not isinstance(ua, str) or not ua.strip():
        raise FetchRefused("user_agent_missing", "a declared User-Agent with a contact is required (no default)")
    ua = ua.strip()
    if not _UA_RE.match(ua) or not _CONTACT_RE.search(ua):
        raise FetchRefused("user_agent_invalid",
                           "User-Agent must be 10-200 printable ASCII chars and include a contact email or URL")
    return ua


class RateLimiter:
    """Spacing limiter: at most `rate_per_s` requests per second across the process. Refuses (rather than
    queueing for long) if the wait would exceed `max_wait_s`. Clock and sleep are injectable for tests."""
    def __init__(self, rate_per_s: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep, max_wait_s: float = 5.0):
        if isinstance(rate_per_s, bool) or not isinstance(rate_per_s, (int, float)) or not (0 < rate_per_s <= MAX_RATE_PER_S):
            raise ValueError(f"rate must be > 0 and <= {MAX_RATE_PER_S} requests/second")
        self.rate, self.interval, self.max_wait_s = float(rate_per_s), 1.0 / float(rate_per_s), max_wait_s
        self._clock, self._sleep, self._next = clock, sleep, 0.0
        self._lock = threading.Lock()

    def acquire(self) -> float:
        with self._lock:
            now = self._clock()
            start = max(now, self._next)
            wait = start - now
            if wait > self.max_wait_s:
                raise FetchRefused("rate_limited", f"rate limit {self.rate}/s: would wait {wait:.1f}s")
            self._next = start + self.interval
        if wait > 0:
            self._sleep(wait)
        return wait


def _check_url(url: str, hosts: frozenset, path_prefixes: Sequence[str]) -> str:
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        raise FetchRefused("bad_url", "unparseable URL")
    if u.scheme != "https":
        raise FetchRefused("not_https", "only https is allowed")
    if u.username or u.password:
        raise FetchRefused("userinfo_in_url", "credentials in URL are refused")
    if port not in (None, 443):
        raise FetchRefused("bad_port", "only the default https port is allowed")
    if (u.hostname or "").lower() not in hosts:
        raise FetchRefused("host_not_allowlisted", "host is not on the allowlist")
    if not any(u.path.startswith(p) for p in path_prefixes):
        raise FetchRefused("path_not_allowlisted", "path is not on the allowlist")
    if u.fragment:
        raise FetchRefused("bad_url", "fragments are refused")
    return url


def guarded_get(transport: Callable, url: str, *, hosts: frozenset, path_prefixes: Sequence[str], user_agent: str,
                limiter: RateLimiter, timeout_s: float, max_bytes: int, max_redirects: int = 2) -> tuple:
    """Returns (final_url, HttpResponse(status 200)). `transport(url, headers, timeout_s, max_bytes)` performs ONE
    request without following redirects. Every hop is re-validated against the allowlist and the rate limiter."""
    ua = validate_user_agent(user_agent)
    headers = {"User-Agent": ua, "Accept": "application/json", "Accept-Encoding": "identity"}
    cur = _check_url(url, frozenset(h.lower() for h in hosts), path_prefixes)
    for hop in range(max_redirects + 1):
        limiter.acquire()
        resp = transport(cur, headers, timeout_s, max_bytes)
        if not isinstance(resp, HttpResponse):
            raise FetchRefused("bad_transport_response", "transport returned an unexpected object")
        if resp.status in REDIRECT_STATUSES:
            loc = (resp.headers or {}).get("location")
            if not loc or hop >= max_redirects:
                raise FetchRefused("too_many_redirects" if loc else "redirect_without_location", "redirect refused")
            try:
                cur = _check_url(urljoin(cur, loc), frozenset(h.lower() for h in hosts), path_prefixes)
            except FetchRefused as e:
                raise FetchRefused("redirect_off_allowlist", f"redirect target refused ({e.code})")
            continue
        if resp.status != 200:
            raise FetchRefused(f"http_status_{resp.status}", f"upstream returned HTTP {resp.status}")
        enc = ((resp.headers or {}).get("content-encoding") or "identity").strip().lower()
        if enc not in ("", "identity"):
            raise FetchRefused("content_encoding_refused", "compressed responses are refused")
        cl = (resp.headers or {}).get("content-length")
        if cl is not None and (not str(cl).isdigit() or int(cl) > max_bytes):
            raise FetchRefused("response_too_large", "declared content-length exceeds the size cap")
        if not isinstance(resp.body, (bytes, bytearray)) or len(resp.body) > max_bytes:
            raise FetchRefused("response_too_large", f"response larger than {max_bytes} bytes")
        ctype = ((resp.headers or {}).get("content-type") or "").split(";")[0].strip().lower()
        if ctype not in ("application/json", "text/json"):
            raise FetchRefused("unexpected_content_type", f"content-type {ctype or 'missing'} is not JSON")
        return cur, resp
    raise FetchRefused("too_many_redirects", "redirect refused")  # pragma: no cover
