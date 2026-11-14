"""Read service credentials without putting their values in process environments."""
import os
from pathlib import Path


def secret(name, env=None):
    env = os.environ if env is None else env
    value, filename = env.get(name), env.get(name + "_FILE")
    if value is not None and filename is not None:
        raise RuntimeError(f"Set only {name} or {name}_FILE")
    if filename is None:
        return value
    data = Path(filename).read_bytes()
    if not data or len(data) > 65536 or b"\x00" in data:
        raise RuntimeError(f"Invalid credential file for {name}")
    # Do not strip whitespace: existing HMAC key bytes must remain identical.
    return data.decode("utf-8")
