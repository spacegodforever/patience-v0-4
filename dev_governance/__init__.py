"""Dev governance: run development actions through PATIENCE's approval gate.

propose -> policy -> approval -> execute (bound to payload hash) -> audit (hash-chained,
append-only, tamper-evident). Adapters here are simulations / dry-runs only.
"""
from .policy import DevPolicy, load_policy, TIERS
from .gate import DevGate, GateError
from .adapters import Adapter, SimulatedGitHubPRAdapter, SimulatedDeployAdapter, default_adapters
from .authority import CapabilityAuthority, AuthorityError

__all__ = ["DevPolicy", "load_policy", "TIERS", "DevGate", "GateError", "Adapter",
           "SimulatedGitHubPRAdapter", "SimulatedDeployAdapter", "default_adapters",
           "CapabilityAuthority", "AuthorityError"]
