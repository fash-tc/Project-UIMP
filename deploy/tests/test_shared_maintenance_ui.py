from pathlib import Path


KEEP_API_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\lib\keep-api.ts")
TYPES_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\lib\types.ts")
ADMIN_PAGE_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\admin\page.tsx")
WEBHOOKS_PAGE_PATH = Path(r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\webhooks\page.tsx")


def test_keep_api_exposes_shared_maintenance_bootstrap_helpers():
    keep_api = KEEP_API_PATH.read_text(encoding="utf-8")

    assert "export async function bootstrapSharedMaintenanceAuth" in keep_api
    assert "export async function fetchSharedMaintenanceAuth" in keep_api
    assert "export async function saveSharedMaintenanceAuth" in keep_api
    assert "export async function testSharedMaintenanceAuth" in keep_api
    assert "export async function clearSharedMaintenanceAuth" in keep_api


def test_types_include_shared_maintenance_auth_metadata():
    types_text = TYPES_PATH.read_text(encoding="utf-8")

    assert "export interface SharedMaintenanceAuthConfig" in types_text


def test_admin_page_contains_shared_maintenance_auth_card():
    page = ADMIN_PAGE_PATH.read_text(encoding="utf-8")

    assert "Shared Maintenance Auth" in page
    assert "fetchSharedMaintenanceAuth" in page
    assert "saveSharedMaintenanceAuth" in page
    assert "testSharedMaintenanceAuth" in page
    assert "clearSharedMaintenanceAuth" in page


def test_webhooks_page_bootstraps_for_admin_and_sre():
    page = WEBHOOKS_PAGE_PATH.read_text(encoding="utf-8")

    assert "bootstrapSharedMaintenanceAuth" in page
    assert "user?.role?.name === 'Admin' || user?.role?.name === 'SRE'" in page
    assert "Shared maintenance auth is not configured." in page


def test_webhooks_page_persists_subscriber_secrets_for_signed_incidents():
    page = WEBHOOKS_PAGE_PATH.read_text(encoding="utf-8")
    keep_api = KEEP_API_PATH.read_text(encoding="utf-8")

    assert "persistWebhookSubscriberSecret" in keep_api
    assert "await persistWebhookSubscriberSecret(subscriber.id, subscriber.name, subscriber.url, subscriber.secret);" in page
    assert "await persistWebhookSubscriberSecret(sub.id, sub.name, sub.url, secret);" in page
