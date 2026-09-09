from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit import audit_identities, posture_score
from models import Identity


def load_identities(path: Path) -> list[Identity]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [Identity(**item) for item in raw]


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit synthetic identity privilege posture")
    parser.add_argument("input", type=Path)
    args = parser.parse_args()

    identities = load_identities(args.input)
    findings = audit_identities(identities)
    payload = {
        "identities_reviewed": len(identities),
        "findings": [f.__dict__ for f in findings],
        "posture_score": posture_score(findings),
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
