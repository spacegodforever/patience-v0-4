"""Optional local Ollama suggestion. Output is advisory text only, always labelled unverified.

Env: PATIENCE_OLLAMA_URL (default http://127.0.0.1:11434), PATIENCE_OLLAMA_MODEL (unset = off).
"""
from __future__ import annotations
import json
import os
import httpx


def model() -> str:
    return os.environ.get("PATIENCE_OLLAMA_MODEL", "")


def url() -> str:
    return os.environ.get("PATIENCE_OLLAMA_URL", "http://127.0.0.1:11434")


def suggest(projects, events) -> dict:
    """{"used": bool, "model", "text"|None, "unverified": True, "llm_error": str|None}"""
    m = model()
    out = {"used": False, "model": m or None, "text": None, "unverified": True, "llm_error": None}
    if not m:
        return out
    prompt = ("You are PATIENCE, a cautious project coordinator. Use only this supplied workspace data. "
              "Do not invent facts. Return concise practical advice.\n"
              + json.dumps({"projects": projects[:8], "recent_events": events[:8]}, default=str))
    try:
        r = httpx.post(f"{url()}/api/chat", timeout=18,
                       json={"model": m, "messages": [{"role": "user", "content": prompt}], "stream": False})
        r.raise_for_status()
        text = (r.json().get("message") or {}).get("content")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("empty model response")
        out.update(used=True, text=text[:4000])
    except Exception as e:  # noqa: BLE001
        out["llm_error"] = f"{type(e).__name__}: {str(e)[:200]}"
    return out


def available() -> bool:
    try:
        return httpx.get(f"{url()}/api/tags", timeout=1.2).status_code == 200
    except Exception:  # noqa: BLE001
        return False
