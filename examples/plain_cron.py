"""Cron job: verify every claim in a JSONL file. Exit 1 if any verdict is not pass.

    PYTHONPATH=src python3 examples/plain_cron.py claims.jsonl contracts/refund.full.stripe.json   # real (env keys)
    python3 examples/plain_cron.py --demo        # offline, one honest + one half refund -> exit 1
    python3 examples/plain_cron.py --demo-good   # offline, all honest -> exit 0
"""
import json, os, sys, tempfile
import _offline
import verify


def run(lines, contract, reader, ledger):
    bad = 0
    for line in lines:
        if not line.strip(): continue
        r = verify.check(contract, json.loads(line), reader, ledger=ledger)
        print(r["verdict"].upper().ljust(13), r["run_id"], *r["reasons"])
        bad += not r["ok"]
    return 1 if bad else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0].startswith("--demo"):
        faults = [None, None] if a[0] == "--demo-good" else [None, "half"]
        p = os.path.join(tempfile.mkdtemp(), "claims.jsonl")
        with open(p, "w") as f: f.writelines(json.dumps(_offline.refund_tool(x)) + "\n" for x in faults)
        sys.exit(run(open(p), _offline.CONTRACT, _offline.READER, _offline.LEDGER))
    if len(a) != 2: sys.exit(__doc__)
    from verify import contract
    from verify.cli import reader_for
    c = contract.load(a[1])
    sys.exit(run(open(a[0]), c, reader_for(c), "verify.db"))
