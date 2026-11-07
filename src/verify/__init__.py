"""Verify: never trust an agent's own "done". Read the system of record back."""
from .core import Blocked, Ledger, evaluate, verify

__all__ = ["Blocked", "Ledger", "evaluate", "verify"]
__version__ = "0.1.0"
