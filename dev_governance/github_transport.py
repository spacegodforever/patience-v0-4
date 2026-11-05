"""Real HTTP transport for the GitHub adapter (stdlib urllib only).

Hard limits, all enforced here regardless of what the adapter builds:
- https://api.github.com only (scheme + exact host allowlist; userinfo/ports rejected)
- redirects are never followed (a 3xx is returned as-is, so it can't bounce the token elsewhere)
- connect/read timeout (default 10 s), response body capped (default 2 MiB)
- methods limited to GET/POST; `read_only=True` refuses anything but GET
- no proxies from the environment (the token never goes via an env-configured proxy)
Errors never include headers, so the token can't leak through exception text.
"""
from __future__ import annotations
import json
import urllib.error
import urllib.request
from typing import Optional
from urllib.parse import urlsplit

ALLOWED_HOSTS = frozenset({"api.github.com"})
ALLOWED_METHODS = frozenset({"GET", "POST"})


class TransportError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # never follow
        return None


def check_url(url: str) -> None:
    u = urlsplit(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS or u.username or u.password or \
            u.port not in (None, 443) or u.netloc.lower() not in ALLOWED_HOSTS:
        raise TransportError("URL not allowed (https://api.github.com only)")


class UrllibTransport:
    def __init__(self, timeout: float = 10.0, max_bytes: int = 2 * 1024 * 1024, read_only: bool = False):
        self.timeout, self.max_bytes, self.read_only = float(timeout), int(max_bytes), read_only
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def __call__(self, req: dict) -> dict:
        method = str(req.get("method", "")).upper()
        if method not in ALLOWED_METHODS or (self.read_only and method != "GET"):
            raise TransportError(f"method {method!r} not allowed by this transport")
        check_url(req["url"])
        body: Optional[bytes] = req["body"].encode() if isinstance(req.get("body"), str) else None
        r = urllib.request.Request(req["url"], data=body, method=method, headers=dict(req.get("headers") or {}))
        try:
            resp = self._opener.open(r, timeout=self.timeout)
            status, headers = resp.status, dict(resp.headers)
            raw = resp.read(self.max_bytes + 1)
        except urllib.error.HTTPError as e:  # includes 3xx (not followed) and 4xx/5xx
            status, headers, raw = e.code, dict(e.headers or {}), e.read(self.max_bytes + 1) if e.fp else b""
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise TransportError(f"network error ({type(e).__name__})") from None
        if len(raw) > self.max_bytes:
            raise TransportError("response too large")
        text = raw.decode("utf-8", "replace")
        ctype = headers.get("Content-Type", "")
        data = text
        if "json" in ctype:
            try:
                data = json.loads(text) if text else None
            except ValueError:
                pass
        safe_headers = {k: v for k, v in headers.items()
                        if k.lower() in ("content-type", "location", "x-ratelimit-remaining", "x-github-request-id")}
        return {"status": status, "headers": safe_headers, "body": data}
