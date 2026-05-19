import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import closing

import pytest


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def admin_api_server():
    """Spawn admin-api.py as a subprocess on a free port; yield (port, proc, db_path)."""
    port = _free_port()
    # NamedTemporaryFile (not the deprecated mktemp); close the handle so Windows
    # lets the subprocess open the same path.
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db_path = tmp.name
    env = {
        **os.environ,
        "API_PORT": str(port),
        "DB_PATH": db_path,
        "AUTH_API_URL": "http://127.0.0.1:1",   # invalid; tests override per-case
        "AUTH_SECRET": "test-secret-32-bytes-long-xxxxxx",
        "CLUSTER_ENDPOINT": "http://127.0.0.1:1",
        "ADMIN_BYPASS_TOKEN": "test-bypass",
    }
    proc = subprocess.Popen(
        [sys.executable, "-u", os.path.join(os.path.dirname(__file__), "..", "admin-api.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        # wait for port to open
        deadline = time.time() + 5
        while time.time() < deadline:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.05)
        else:
            try:
                out, _ = proc.communicate(timeout=2)
                out_text = out.decode() if out else ""
            except subprocess.TimeoutExpired:
                out_text = "(timed out reading admin-api stdout)"
            raise RuntimeError(f"admin-api failed to start. Output:\n{out_text}")
        yield port, proc, db_path
    finally:
        proc.terminate()
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        if os.path.exists(db_path):
            os.unlink(db_path)
