"""The ONLY module in oracle_intelligence that touches the network (stdlib http.client over verified TLS).

One request per call, redirects are never followed here (connectors.guarded_get validates each hop), no proxy
environment variables are consulted, TLS certificate and hostname verification are on, the body is read in
bounded chunks against both a byte cap and a wall-clock deadline. Never imported by tests' default paths.
"""
from __future__ import annotations
import http.client
import ssl
import time
from urllib.parse import urlsplit

from .connectors import FetchRefused, HttpResponse


def https_transport(url: str, headers: dict, timeout_s: float, max_bytes: int) -> HttpResponse:
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise FetchRefused("not_https", "only https is allowed")
    ctx = ssl.create_default_context()
    deadline = time.monotonic() + timeout_s
    conn = http.client.HTTPSConnection(u.hostname, 443, timeout=timeout_s, context=ctx)
    try:
        conn.request("GET", (u.path or "/") + (("?" + u.query) if u.query else ""), headers=headers)
        r = conn.getresponse()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        if r.status in (301, 302, 303, 307, 308):
            return HttpResponse(r.status, hdrs, b"")
        cl = hdrs.get("content-length")
        if cl is not None and cl.isdigit() and int(cl) > max_bytes:
            raise FetchRefused("response_too_large", "declared content-length exceeds the size cap")
        chunks, total = [], 0
        while True:
            if time.monotonic() > deadline:
                raise FetchRefused("timeout", "overall fetch deadline exceeded")
            b = r.read(65536)
            if not b:
                break
            total += len(b)
            if total > max_bytes:
                raise FetchRefused("response_too_large", f"response larger than {max_bytes} bytes")
            chunks.append(b)
        return HttpResponse(r.status, hdrs, b"".join(chunks))
    finally:
        conn.close()
