from pathlib import Path


ALERTS_TABLE_VIEW_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\command-center\AlertsTableView.tsx")


def test_resolved_view_uses_last_received_as_primary_time_column():
    source = ALERTS_TABLE_VIEW_PATH.read_text(encoding="utf-8")

    assert "const isResolvedView = statusFilter === 'resolved';" in source
    assert "Last Received" in source
    assert "{timeAgo(alert.lastReceived)}" in source
    assert "{timeAgo(alertStartTime(alert))}" in source
    assert source.index("Last Received") < source.index("AI Summary")


def test_resolved_view_resets_sort_to_time_desc():
    source = ALERTS_TABLE_VIEW_PATH.read_text(encoding="utf-8")

    assert "useEffect(() => {" in source
    assert "if (statusFilter === 'resolved')" in source
    assert "setSortField('time');" in source
    assert "setSortDir('desc');" in source
