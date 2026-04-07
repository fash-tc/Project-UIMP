from pathlib import Path


DASHBOARD_VIEW_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\command-center\DashboardView.tsx")
COMMAND_CENTER_PAGE_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\command-center\page.tsx")
BULK_TICKET_MODAL_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\command-center\BulkIncidentTicketModal.tsx")
KEEP_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\lib\keep-api.ts")


def test_bulk_ticket_modal_description_excludes_ai_summary():
    source = BULK_TICKET_MODAL_PATH.read_text(encoding="utf-8")

    assert "Summary: ${enrichment.summary}" not in source


def test_bulk_ticket_modal_is_scrollable():
    source = BULK_TICKET_MODAL_PATH.read_text(encoding="utf-8")

    assert "overflow-y-auto" in source


def test_dashboard_view_contains_group_controls_menu():
    source = DASHBOARD_VIEW_PATH.read_text(encoding="utf-8")

    assert "Group Controls" in source
    assert "Manage this custom group outside the alert table" in source
    assert "fixed inset-0 z-[125]" in source


def test_command_center_create_group_modal_supports_existing_group_append():
    source = COMMAND_CENTER_PAGE_PATH.read_text(encoding="utf-8")

    assert "selectedGroupMode" in source
    assert "existingGroups" in source


def test_keep_api_exposes_custom_group_rename_and_append_helpers():
    source = KEEP_API_PATH.read_text(encoding="utf-8")

    assert "renameCustomAlertGroup" in source
    assert "addAlertsToCustomAlertGroup" in source
