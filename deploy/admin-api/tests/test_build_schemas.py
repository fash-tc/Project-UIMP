import json
import os
import subprocess
import sys
from pathlib import Path


def test_generator_writes_expected_keys(tmp_path):
    # Generate to tmp; compare contents
    here = Path(__file__).resolve().parent.parent
    out = subprocess.check_output([sys.executable, str(here / "build_schemas.py")], text=True)
    assert "wrote" in out
    schemas = (here.parent / "uip_config_client" / "schemas.py").read_text()
    seed = json.loads((here / "seeds" / "config_seed.json").read_text())
    for key in seed["keys"]:
        assert key in schemas, f"key {key} missing from generated schemas"
    assert f"SEED_VERSION = {seed['version']}" in schemas
