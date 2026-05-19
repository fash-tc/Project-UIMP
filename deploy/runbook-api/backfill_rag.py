"""
One-shot backfill: read every row from the runbook-api SQLite DB and push
it into the cluster's rag-search service so semantic match works for
historical entries on day one.

Idempotent — re-running it just re-embeds and overwrites by id.

Usage on the UIP host:

    docker compose exec runbook-api python3 /app/backfill_rag.py

Env vars (same defaults as runbook-api.py):
    DB_PATH         — runbook SQLite path (default /data/runbook.db)
    RAG_SEARCH_URL  — rag-search base URL
    RAG_COLLECTION  — collection name (default sre_runbooks)
"""

import json
import os
import sqlite3
import sys
import time
from urllib.request import Request, urlopen

DB_PATH = os.environ.get("DB_PATH", "/data/runbook.db")
RAG_SEARCH_URL = os.environ.get(
    "RAG_SEARCH_URL", "http://aicompute01.cnco1.tucows.cloud:31445"
).rstrip("/")
RAG_COLLECTION = os.environ.get("RAG_COLLECTION", "sre_runbooks")


def _post(path, body, timeout=30):
    req = Request(
        f"{RAG_SEARCH_URL}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _text(alert_name, remediation):
    rem = (remediation or "").strip()
    if len(rem) > 1500:
        rem = rem[:1500]
    return f"{(alert_name or '').strip()}\n\n{rem}".strip()


def main():
    if not RAG_SEARCH_URL:
        print("RAG_SEARCH_URL is empty, nothing to do", file=sys.stderr)
        sys.exit(2)

    print(f"backfill: source={DB_PATH} -> {RAG_SEARCH_URL}/v1/collections/{RAG_COLLECTION}")
    _post(f"/v1/collections/{RAG_COLLECTION}/init", {})

    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    rows = db.execute(
        "SELECT id, alert_name, remediation, hostname, service, severity "
        "FROM runbook_entries ORDER BY id ASC"
    ).fetchall()
    total = len(rows)
    print(f"backfill: {total} rows to embed")

    ok = 0
    failed = []
    for idx, row in enumerate(rows, 1):
        text = _text(row["alert_name"], row["remediation"])
        if not text:
            print(f"  [{idx}/{total}] id={row['id']} skipped (empty text)")
            continue
        body = {
            "id": int(row["id"]),
            "text": text,
            "metadata": {
                "hostname": (row["hostname"] or "").lower(),
                "service": (row["service"] or "").lower(),
                "severity": (row["severity"] or "").lower(),
            },
        }
        try:
            _post(f"/v1/collections/{RAG_COLLECTION}/upsert", body)
            ok += 1
            if idx % 50 == 0 or idx == total:
                print(f"  [{idx}/{total}] ok={ok} fail={len(failed)}")
        except Exception as exc:
            failed.append((row["id"], str(exc)))
            print(f"  [{idx}/{total}] id={row['id']} FAILED: {exc}")
            # short backoff so a transient outage doesn't burn through retries
            time.sleep(0.5)

    print()
    print(f"done: {ok}/{total} embedded, {len(failed)} failures")
    if failed:
        for entry_id, err in failed[:20]:
            print(f"  id={entry_id}: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
