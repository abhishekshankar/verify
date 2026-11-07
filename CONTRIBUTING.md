# Contributing
- Python 3.10+, stdlib only in `src/verify` (no runtime dependencies).
- Run `PYTHONPATH=src python3 -m unittest discover -s tests` before a PR.
- New adapter: a reader `(sor, claim) -> (fields, raw_json)`, a contract, and an offline fake with a `check()` like `hubspot.py`.
- Never put keys in code, tests or issues. Tests use fakes only.
- CI for outside contributors runs after a maintainer approves.
