from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_statuspage_tab_shows_active_count_badge():
    dashboard = (ROOT / "sre-frontend" / "src" / "app" / "command-center" / "DashboardView.tsx").read_text(encoding="utf-8")
    tab = ROOT / "sre-frontend" / "src" / "app" / "command-center" / "StatuspageTab.tsx"

    assert tab.exists()
    assert "setDashboardTab('statuspage')" in dashboard
    assert "statuspageIncidentCount" in dashboard
    assert "{statuspageIncidentCount > 0 && (" in dashboard
    assert "Statuspage" in dashboard


def test_statuspage_tab_contains_active_incidents_controls():
    text = (ROOT / "sre-frontend" / "src" / "app" / "command-center" / "StatuspageTab.tsx").read_text(encoding="utf-8")

    assert "fetchStatuspageIncidents" in text
    assert "Active Incidents" in text
    assert "Open in Statuspage" in text
