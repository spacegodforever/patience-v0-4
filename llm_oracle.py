"""Pluggable LLM-backed Oracle (OpenAI-compatible /chat/completions).

Env vars: PATIENCE_LLM_BASE_URL (e.g. https://api.openai.com/v1),
PATIENCE_LLM_API_KEY, PATIENCE_LLM_MODEL, PATIENCE_LLM_TIMEOUT (seconds, default 20).
If no key/base URL/model is set, or the call/parse/validation fails, the
heuristic Oracle is used. `last_path` records "llm" or "heuristic" and
`last_error` the fallback reason.
"""
from __future__ import annotations
import json
import os
import re
import urllib.request
from typing import Any, Dict, Optional
from models import Assessment, Observation, PatienceState
from oracle import Oracle

SCORE_FIELDS = ("relevance", "urgency", "uncertainty", "consequence", "opportunity", "confidence")
LIST_FIELDS = ("evidence", "assumptions", "unknowns", "competing_explanations")

SYSTEM_PROMPT = (
    "You are the PATIENCE Oracle. Assess the observation against the mission. "
    "Reply with ONLY a JSON object with keys: "
    + ", ".join(SCORE_FIELDS) + " (numbers in [0,1]) and "
    + ", ".join(LIST_FIELDS) + " (arrays of short strings). No prose."
)


class AssessmentValidationError(ValueError):
    pass


def parse_assessment(text: str) -> Assessment:
    """Extract a JSON object from model text and validate it into an Assessment."""
    match = re.search(r"\{.*\}", text or "", re.S)
    if not match:
        raise AssessmentValidationError("no JSON object in model output")
    try:
        data = json.loads(match.group(0))
    except ValueError as e:
        raise AssessmentValidationError(f"invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise AssessmentValidationError("JSON is not an object")
    out: Dict[str, Any] = {}
    for k in SCORE_FIELDS:
        v = data.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= float(v) <= 1:
            raise AssessmentValidationError(f"{k} must be a number in [0,1], got {v!r}")
        out[k] = float(v)
    for k in LIST_FIELDS:
        v = data.get(k, [])
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise AssessmentValidationError(f"{k} must be a list of strings")
        out[k] = [x[:500] for x in v[:20]]
    if not out["evidence"]:
        raise AssessmentValidationError("evidence must not be empty")
    return Assessment(**out)


class LLMOracle(Oracle):
    def __init__(self, base_url=None, api_key=None, model=None, timeout=None, env=None):
        env = os.environ if env is None else env
        self.base_url = (base_url or env.get("PATIENCE_LLM_BASE_URL") or "").rstrip("/")
        self.api_key = api_key or env.get("PATIENCE_LLM_API_KEY") or ""
        self.model = model or env.get("PATIENCE_LLM_MODEL") or ""
        self.timeout = float(timeout or env.get("PATIENCE_LLM_TIMEOUT") or 20)
        self.last_path = "heuristic"
        self.last_error: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)

    def _call(self, obs: Observation, state: PatienceState) -> str:
        user = json.dumps({
            "mission": state.mission, "objective": state.current_objective,
            "priority": state.priority,
            "observation": {"content": obs.content, "source": obs.source, "reliability": obs.reliability},
        })
        body = json.dumps({
            "model": self.model, "temperature": 0,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}],
        }).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + "/chat/completions", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload["choices"][0]["message"]["content"]

    def assess(self, obs: Observation, state: PatienceState) -> Assessment:
        self.last_error = None
        if not self.configured:
            self.last_path = "heuristic"
            self.last_error = "no LLM configured"
            return super().assess(obs, state)
        try:
            a = parse_assessment(self._call(obs, state))
            # Safety floor: the model can never lower consequence below the rule-based score.
            floor = super().assess(obs, state).consequence
            if a.consequence < floor:
                a.consequence = floor
            self.last_path = "llm"
            return a
        except Exception as e:  # network, HTTP, parse, validation
            self.last_path = "heuristic"
            self.last_error = f"{type(e).__name__}: {e}"[:300]
            return super().assess(obs, state)
