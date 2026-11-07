"""verify demo {local,stripe,zendesk} | verify selfcheck | verify ledger <db>"""
import sys
from . import local, stripe, zendesk
from .core import Ledger


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    if a[:2] == ["demo", "local"]: local.demo()
    elif a[:2] == ["demo", "stripe"]: stripe.main()
    elif a[:2] == ["demo", "zendesk"]: zendesk.main()
    elif a[:1] == ["selfcheck"]:
        local.check(); stripe.check(); zendesk.check()
    elif a[:1] == ["ledger"] and len(a) == 2:
        led = Ledger(a[1])
        for row in led.db.execute("SELECT run_id, verdict, level_reached, independence, reasons_json FROM verdict"):
            print(*row, sep="  ")
        ok = led.verify_chain()
        print("hash chain intact:", ok)
        return 0 if ok else 1
    else:
        print(__doc__); return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
