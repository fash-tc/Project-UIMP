from pathlib import Path


KEEP_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\lib\keep-api.ts")
COMMAND_CENTER_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\command-center\page.tsx")
ALERT_STATE_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\alert-state-api\alert-state-api.py")


def test_keep_api_incident_state_helpers_include_firing_start_fields():
    text = KEEP_API_PATH.read_text(encoding="utf-8")

    assert "firingStart?: string" in text
    assert "firingStarts?: Record<string, string>" in text
    assert "firing_start: firingStart || ''" in text
    assert "firing_starts: firingStarts || {}" in text


def test_command_center_refire_logic_no_longer_uses_incident_created_at():
    text = COMMAND_CENTER_PATH.read_text(encoding="utf-8")

    assert "incident_created_at ||" not in text
    assert "storeIncidentStateBulk(fingerprints, result.issueKey, result.issueUrl || '', firingStarts)" in text
    assert "await storeIncidentState(" in text
    assert "alert.firingStartTime || alert.startedAt || ''" in text


def test_alert_state_api_incident_storage_persists_firing_start_baseline():
    text = ALERT_STATE_API_PATH.read_text(encoding="utf-8")

    assert 'firing_start = (data.get("firing_start") or "").strip()' in text
    assert 'firing_starts = data.get("firing_starts") or {}' in text
    assert "ack_firing_start = excluded.ack_firing_start" in text
    assert "incident_created_at = excluded.incident_created_at" in text
