"""Regenerates uip_config_client/schemas.py from config_seed.json.

Run from repo root: python deploy/admin-api/build_schemas.py

Output: deploy/uip_config_client/schemas.py — a frozen dataclass dict that
consumers load to validate SSE payloads (spec §5.5.1).
"""
import json
import os
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SEED = HERE / "seeds" / "config_seed.json"
OUT = HERE.parent / "uip_config_client" / "schemas.py"

HEADER = '''"""GENERATED FILE. Do not edit by hand.

Regenerate with: python deploy/admin-api/build_schemas.py

Source: deploy/admin-api/seeds/config_seed.json
"""
from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class KeySchema:
    value_type: Literal["int", "float", "string", "bool", "json", "secret"]
    validation_rule: dict | None
    seed_version: int


'''


def render() -> str:
    seed = json.loads(SEED.read_text())
    seed_version = int(seed.get("version", 1))
    lines = [HEADER, f"SEED_VERSION = {seed_version}\n\n", "SCHEMAS: dict[str, KeySchema] = {\n"]
    for key in sorted(seed["keys"]):
        entry = seed["keys"][key]
        vt = entry["value_type"]
        v = entry.get("validation")
        v_repr = repr(v) if v is not None else "None"
        lines.append(
            f"    {key!r}: KeySchema(value_type={vt!r}, validation_rule={v_repr}, seed_version={seed_version}),\n"
        )
    lines.append("}\n")
    return "".join(lines)


def main() -> int:
    out_dir = OUT.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    # __init__.py is hand-authored in Task 6 Step 2 and intentionally not
    # overwritten here; the generator owns ONLY schemas.py.
    OUT.write_text(render())
    print(f"wrote {OUT} ({len(json.loads(SEED.read_text())['keys'])} keys)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
