"""Run inside the container after deploying: python /app/verify_admin_tab_seed.py"""
import sqlite3
import sys

db = sqlite3.connect("/data/auth.db")
expected = ["manage_ai", "manage_pipeline", "manage_zabbix", "manage_integrations",
            "manage_services", "manage_features", "manage_runbooks", "view_audit"]
for role_id, role_name, expected_perms in [(1, "Admin", expected), (2, "SRE", expected), (3, "Viewer", ["view_audit"])]:
    rows = db.execute("SELECT permission FROM role_permissions WHERE role_id=?", (role_id,)).fetchall()
    perms = {r[0] for r in rows}
    missing = set(expected_perms) - perms
    if missing:
        print(f"FAIL: {role_name} missing {missing}")
        sys.exit(1)
print("OK: all roles have correct admin-tab perms")
