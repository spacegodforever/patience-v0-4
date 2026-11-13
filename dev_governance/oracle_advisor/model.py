"""Provider-agnostic model interface, a deterministic offline stub, and an opt-in local Ollama backend.

Rules every backend follows (tested): no side effects on PATIENCE, no `tools`/`functions` sent,
response bytes capped, errors carry an enum `code` (never free text into the audit log), and the
reported model id must match the configured one. No cloud/hosted backend exists in step 1.
Ollama is OFF unless PATIENCE_ORACLE=ollama AND PATIENCE_ORACLE_OLLAMA_MODEL are both set, and it
only talks to a loopback host over plain http.
"""
from __future__ import annotations
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol, Union
from urllib.parse import urlsplit

ERROR_CODES = ("disabled", "unreachable", "timeout", "http_error", "oversize_response", "model_mismatch",
               "truncated_prompt", "busy", "bad_encoding", "bad_response")


class OracleModelError(Exception):
    """Any backend failure. `code` is an enum so audit events never carry free text."""
    def __init__(self, code: str, detail: str = ""):
        if code not in ERROR_CODES:
            code = "http_error"
        super().__init__(code)
        self.code, self.detail = code, str(detail)[:200]  # detail is for local debugging only


@dataclass(frozen=True)
class ModelLimits:
    timeout_s: float = 10.0       # total deadline for one call (enforced by the service, not just a socket timeout)
    max_prompt_chars: int = 12000  # system + user text; over this the Oracle is skipped, never truncated
    max_output_bytes: int = 32 * 1024
    max_output_tokens: int = 700
    num_ctx: int = 8192
    version: str = "limits-v1"


@dataclass(frozen=True)
class ModelRequest:
    system: str
    user: str
    schema: dict            # JSON Schema of the recommendation; some backends use it to constrain output
    limits: ModelLimits
    temperature: float = 0.0
    seed: Optional[int] = 0


@dataclass(frozen=True)
class ModelResponse:
    text: str               # raw model text; validated by schema.py, never trusted
    backend: str
    model_id: str           # id the backend reports back
    latency_ms: int = 0
    prompt_tokens: Optional[int] = None
    output_tokens: Optional[int] = None


class OracleModel(Protocol):
    name: str               # configured model id
    backend: str
    is_local: bool
    def generate(self, req: ModelRequest) -> ModelResponse: ...  # raises OracleModelError


# ---------------------------------------------------------------- deterministic stub (tests/offline)
Scripted = Union[str, Callable[[ModelRequest], str], BaseException]


class StubModel:
    """Deterministic offline provider. Returns scripted text, raises a scripted exception, or (default)
    a fixed, schema-valid `ask_human` recommendation citing the first context item in the prompt.
    Makes no network call and reads no file."""
    backend = "stub"
    is_local = True

    def __init__(self, script: Optional[Scripted] = None, name: str = "stub-v1", reported_name: Optional[str] = None):
        self.script, self.name, self._reported = script, name, reported_name or name
        self.calls: list = []

    def generate(self, req: ModelRequest) -> ModelResponse:
        self.calls.append(req)
        s = self.script
        if isinstance(s, BaseException):
            raise s
        if callable(s):
            text = s(req)
        elif s is None:
            text = self._default(req)
        else:
            text = s
        return ModelResponse(text=text, backend=self.backend, model_id=self._reported, latency_ms=0)

    @staticmethod
    def _default(req: ModelRequest) -> str:
        m = re.search(r"<<<ITEM id=(ctx:[A-Za-z0-9_.\-]{1,64}) kind=([a-z_]+)", req.user)
        ref, kind = (m.group(1), m.group(2)) if m else ("ctx:none", "request_text")
        return json.dumps({
            "schema_version": "oracle-rec-v1", "action": "ask_human",
            "rationale": "Deterministic stub: no model reasoning was performed.",
            "basis": [{"fact": "The request was supplied by the caller.", "source": {"kind": kind, "ref": ref}}],
            "confidence": {"level": "low", "reason": "stub provider; not a real assessment"},
            "unknowns": ["whether the request is safe to act on"],
            "risk_hint": {"floor": "low", "reason": "stub provider has no opinion"}})


# ---------------------------------------------------------------- local Ollama (opt-in)
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # never follow
        return None


def check_ollama_url(url: str) -> str:
    """Plain http, loopback host only, no userinfo/path/query. Returns the normalized base URL."""
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        raise OracleModelError("disabled", "bad url")
    if u.scheme != "http" or (u.hostname or "").lower() not in LOOPBACK_HOSTS or u.username or u.password \
            or u.path not in ("", "/") or u.query or u.fragment:
        raise OracleModelError("disabled", "ollama url must be http://<loopback>[:port]")
    host = f"[{u.hostname}]" if ":" in (u.hostname or "") else u.hostname
    return f"http://{host}:{port or 11434}"


def _default_post(url: str, body: bytes, timeout: float, max_bytes: int) -> tuple:
    """POST JSON; no redirects, no env proxies, bounded read. Returns (status, raw_bytes)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    r = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        resp = opener.open(r, timeout=timeout)
        return resp.status, resp.read(max_bytes + 1)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, TimeoutError) or isinstance(e, TimeoutError):
            raise OracleModelError("timeout", type(e).__name__)
        raise OracleModelError("unreachable", type(e).__name__)


@dataclass(frozen=True)
class OllamaConfig:
    model: str
    base_url: str = DEFAULT_OLLAMA_URL


class OllamaModel:
    """Local Ollama /api/chat (stream false). Only constructed from an explicit OllamaConfig; the
    URL is re-validated here, so a non-loopback host cannot be used even by direct construction.
    `post` is injectable so tests never open a socket. NOTE: the request/response field names follow
    Ollama's public API docs; this class has NOT been run against a live Ollama in this repo."""
    backend = "ollama"
    is_local = True

    def __init__(self, cfg: OllamaConfig, post: Callable[[str, bytes, float, int], tuple] = _default_post):
        if not isinstance(cfg, OllamaConfig) or not cfg.model or not cfg.model.strip():
            raise OracleModelError("disabled", "ollama model not configured")
        self.name = cfg.model.strip()
        self.base = check_ollama_url(cfg.base_url)
        self._post = post

    def generate(self, req: ModelRequest) -> ModelResponse:
        lim = req.limits
        body = {"model": self.name, "stream": False, "format": req.schema,
                "messages": [{"role": "system", "content": req.system}, {"role": "user", "content": req.user}],
                "options": {"temperature": req.temperature, "seed": req.seed, "num_ctx": lim.num_ctx,
                            "num_predict": lim.max_output_tokens}}  # deliberately no tools/functions
        raw_body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        status, raw = self._post(self.base + "/api/chat", raw_body, lim.timeout_s, lim.max_output_bytes + 4096)
        if status != 200:
            raise OracleModelError("http_error", f"status {status}")
        if len(raw) > lim.max_output_bytes + 4096:
            raise OracleModelError("oversize_response")
        try:
            data = json.loads(raw.decode("utf-8"))
            text = data["message"]["content"]
            reported = data["model"]
        except (UnicodeDecodeError, ValueError, KeyError, TypeError):
            raise OracleModelError("bad_response")
        if not isinstance(text, str) or not isinstance(reported, str):
            raise OracleModelError("bad_response")
        if reported != self.name:
            raise OracleModelError("model_mismatch")
        pt, ot = data.get("prompt_eval_count"), data.get("eval_count")
        pt = pt if isinstance(pt, int) and not isinstance(pt, bool) else None
        ot = ot if isinstance(ot, int) and not isinstance(ot, bool) else None
        if pt is not None and pt >= lim.num_ctx:  # prompt filled the window: it may have been cut silently
            raise OracleModelError("truncated_prompt")
        return ModelResponse(text=text, backend=self.backend, model_id=reported, prompt_tokens=pt, output_tokens=ot)


def oracle_model_from_env(env: Optional[dict] = None, post: Optional[Callable] = None) -> Optional[OracleModel]:
    """None (Oracle disabled) unless PATIENCE_ORACLE=ollama and PATIENCE_ORACLE_OLLAMA_MODEL are set and
    the URL is a loopback http URL. Any other value, or a bad config, means disabled."""
    e = os.environ if env is None else env
    if (e.get("PATIENCE_ORACLE") or "").strip().lower() != "ollama":
        return None
    model = (e.get("PATIENCE_ORACLE_OLLAMA_MODEL") or "").strip()
    if not model:
        return None
    try:
        cfg = OllamaConfig(model, (e.get("PATIENCE_ORACLE_OLLAMA_URL") or DEFAULT_OLLAMA_URL).strip())
        return OllamaModel(cfg, post) if post else OllamaModel(cfg)
    except OracleModelError:
        return None
