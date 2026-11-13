"""Smarter Oracle, step 1: provider-agnostic model adapter + strict structured recommendation.

ADVISORY ONLY. Nothing in this package approves, denies, executes, issues a permit, uses a
capability grant, or lowers a risk tier. The only thing it can do to the gate is hand a validated
recommendation to `DevGate.propose` (see `routing.py`), exactly like any other proposer.
Any failure produces "no recommendation" (labelled unknown), never an action.

Design: /docs/oracle-step1.md. Not wired into `api.dev_gate()` yet (that is a later step).
"""
from .model import (OracleModel, OracleModelError, ModelLimits, ModelRequest, ModelResponse, StubModel,
                    OllamaConfig, OllamaModel, oracle_model_from_env)
from .schema import (SCHEMA_VERSION, Recommendation, RejectCode, SchemaRejection, parse_strict, validate_output,
                     cap_floor, effective_tier, RISK_HINT_CAP, NON_ACTIONS)
from .service import (OracleService, AdviceRequest, ContextItem, AdviceResult, action_catalog, ORACLE_VERSION,
                      oracle_service_from_env)
from .routing import propose_recommendation, RoutingRefused

__all__ = [n for n in dir() if not n.startswith("_")]
