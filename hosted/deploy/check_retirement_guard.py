#!/usr/bin/env python3
"""Offline CI guard: every legacy resource must remain blocked by default."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
RESOURCE = re.compile(r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)


def check(directory=ROOT):
    guard = (directory / "retirement_guard.tf").read_text()
    assert re.search(r'variable\s+"legacy_recovery_authorization"\s*\{', guard), "Missing recovery variable"
    assert re.search(r'^\s*default\s*=\s*""\s*$', guard, re.MULTILINE), "Legacy apply must be disabled by default"
    assert re.search(r'^\s*condition\s*=\s*var\.legacy_recovery_authorization\s*==\s*"REVIEWED-LEGACY-DISASTER-RECOVERY-ONLY"\s*$', guard, re.MULTILINE), "Default-deny precondition changed"
    found = []
    for path in directory.glob("*.tf"):
        text = path.read_text()
        matches = list(RESOURCE.finditer(text))
        for index, match in enumerate(matches):
            address = ".".join(match.groups())
            if address == "terraform_data.legacy_retirement_guard":
                continue
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            block = text[match.end():end]
            declarations = re.findall(r'^\s*depends_on\s*=\s*\[([^\]]*)\]', block, re.MULTILINE)
            assert any("terraform_data.legacy_retirement_guard" in [item.strip() for item in items.split(",")]
                       for items in declarations), "Unprotected legacy resource: " + address
            found.append(address)
    assert len(found) == 29, "Legacy resource inventory changed; review each address before updating this guard"
    return found


if __name__ == "__main__":
    print("Legacy Terraform apply is disabled by default; all %d original resource blocks depend on the retirement guard." % len(check()))
