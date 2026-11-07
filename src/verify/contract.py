"""Load and validate outcome contracts (JSON). Rules from the outcome contract schema v0.1."""
import json
from .core import OPS

REQUIRED = ("id", "version", "owner", "target_system", "subject_ref", "postconditions",
            "required_level", "settle_window_s", "max_attempts", "scope")
LEVELS = ("L1", "L2", "L3", "L4")


def validate(c):
    """Return a list of problems; empty means valid. Rejected at registration, never at runtime."""
    errs = [f"missing field: {f}" for f in REQUIRED if f not in c]
    if errs: return errs
    if not c["postconditions"]: errs.append("postconditions must not be empty")
    if c["required_level"] not in LEVELS: errs.append(f"required_level must be one of {LEVELS}")
    if not isinstance(c["max_attempts"], int) or c["max_attempts"] < 1: errs.append("max_attempts must be an int >= 1")
    if not isinstance(c["settle_window_s"], (int, float)) or c["settle_window_s"] < 0: errs.append("settle_window_s must be >= 0")
    scope = set(c["scope"])
    for group in ("preconditions", "postconditions", "forbidden"):
        for i, chk in enumerate(c.get(group, [])):
            where = f"{group}[{i}]"
            if chk.get("op") not in OPS: errs.append(f"{where}: unknown op {chk.get('op')!r}")
            if chk.get("path") not in scope: errs.append(f"{where}: path {chk.get('path')!r} not in scope")
    sp = c.get("subject_present")
    if sp and sp not in scope: errs.append(f"subject_present {sp!r} not in scope")
    return errs


def load(path):
    with open(path) as f: c = json.load(f)
    errs = validate(c)
    if errs: raise ValueError(f"{path}: invalid contract:\n  " + "\n  ".join(errs))
    return c
