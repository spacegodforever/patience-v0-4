"""UrllibTransport: host allowlist, no redirects, timeouts, read-only mode. No real network:
the urllib opener is replaced and sockets are blocked."""
import io
import socket
import urllib.error

import pytest

from dev_governance.github_transport import TransportError, UrllibTransport, check_url, _NoRedirect

TOKEN = "ghp_FAKE_never_real_0123456789"


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network attempted")
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)


class Resp:
    def __init__(self, status=200, body=b'{"ok": true}', ctype="application/json"):
        self.status, self._b = status, io.BytesIO(body)
        self.headers = {"Content-Type": ctype, "Authorization": "should-be-dropped"}

    def read(self, n=-1):
        return self._b.read(n)


class Opener:
    def __init__(self, result):
        self.result, self.calls = result, []

    def open(self, req, timeout=None):
        self.calls.append((req, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def tx(result, **kw):
    t = UrllibTransport(**kw)
    t._opener = Opener(result)
    return t


def req(url="https://api.github.com/repos/a/b", method="GET", body=None):
    return {"method": method, "url": url, "headers": {"Authorization": f"Bearer {TOKEN}"}, "body": body}


@pytest.mark.parametrize("url", [
    "http://api.github.com/x", "https://evil.com/x", "https://api.github.com.evil.com/x",
    "https://user:pw@api.github.com/x", "https://api.github.com:8443/x", "https://github.com/x",
    "https://API.GITHUB.COM@evil.com/x"])
def test_only_api_github_com_https(url):
    with pytest.raises(TransportError):
        check_url(url)
    t = tx(Resp())
    with pytest.raises(TransportError):
        t(req(url))
    assert t._opener.calls == []


def test_get_parses_json_passes_timeout_and_strips_headers():
    t = tx(Resp(), timeout=3)
    out = t(req())
    assert out == {"status": 200, "headers": {"Content-Type": "application/json"}, "body": {"ok": True}}
    assert t._opener.calls[0][1] == 3.0


def test_redirect_is_not_followed():
    assert _NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.com") is None
    e = urllib.error.HTTPError("https://api.github.com/x", 301, "moved",
                               {"Location": "https://evil.com/steal", "Content-Type": "text/plain"}, io.BytesIO(b""))
    out = tx(e)(req())
    assert out["status"] == 301 and out["headers"]["Location"] == "https://evil.com/steal"


def test_http_error_returns_status_without_token():
    e = urllib.error.HTTPError("https://api.github.com/x", 404, "nf", {"Content-Type": "application/json"},
                               io.BytesIO(b'{"message":"Not Found"}'))
    out = tx(e)(req())
    assert out["status"] == 404 and TOKEN not in str(out)


def test_network_error_text_has_no_token():
    t = tx(urllib.error.URLError(f"failed with {TOKEN}"))
    with pytest.raises(TransportError) as ei:
        t(req())
    assert TOKEN not in str(ei.value)


def test_read_only_refuses_post_and_unknown_methods():
    t = tx(Resp(), read_only=True)
    with pytest.raises(TransportError):
        t(req(method="POST", body="{}"))
    with pytest.raises(TransportError):
        tx(Resp())(req(method="DELETE"))
    assert t._opener.calls == []


def test_response_size_cap():
    with pytest.raises(TransportError, match="too large"):
        tx(Resp(body=b"x" * 100), max_bytes=10)(req())


def test_no_env_proxy(monkeypatch):
    import urllib.request
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.evil:8080")
    t = UrllibTransport()
    ph = [h for h in t._opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert all(h.proxies == {} for h in ph)  # env proxy handler never installed
