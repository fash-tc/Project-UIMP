from pathlib import Path


def test_local_test_subscriber_detection_is_not_hardcoded_to_localhost():
    page = Path(
        r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\webhooks\page.tsx"
    ).read_text(encoding="utf-8")

    assert "parsed.pathname === '/api/webhooks/receive-test'" in page
    assert "sub.url.includes('/api/webhooks/receive-test')" in page
    assert "localhost:8000/api/webhooks/receive-test" not in page


def test_webhook_delete_falls_back_to_archive_for_server_errors():
    page = Path(
        r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\webhooks\page.tsx"
    ).read_text(encoding="utf-8")

    assert "setSubscribers(subs.filter(sub => sub.is_active));" in page
    assert "If hard delete is unavailable upstream, UIP will archive it instead." in page
    assert "if (err && !/internal server error|http 500/i.test(err))" in page
    assert "await updateWebhookSubscriber(sub.id, { is_active: false });" in page


def test_delivery_log_can_infer_incident_type_from_captured_payload():
    page = Path(
        r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\webhooks\page.tsx"
    ).read_text(encoding="utf-8")

    assert "function inferCapturedDeliveryType" in page
    assert "capture.body?.incident" in page
    assert "capture.body.notices.some((notice: any) => notice?.event_type === 'incident')" in page
    assert "const displayType = getDisplayDeliveryType(d, rowCapture);" in page
    assert "{getDisplayDeliveryType(selectedDelivery, matchingCapture)}" in page


def test_delivery_log_includes_unmatched_preview_captures_as_synthetic_rows():
    page = Path(
        r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\webhooks\page.tsx"
    ).read_text(encoding="utf-8")

    assert "function hasNearbyDelivery" in page
    assert "const syntheticPreviewDeliveries: WebhookDelivery[] =" in page
    assert ".filter((capture) => !hasNearbyDelivery(deliveries, capture, previewSubscriberId))" in page
    assert "id: -capture.id" in page
    assert "const displayedDeliveries = [...syntheticPreviewDeliveries, ...deliveries]" in page
    assert ".sort((a, b) => parseWebhookTimestamp(b.timestamp).getTime() - parseWebhookTimestamp(a.timestamp).getTime())" in page


def test_delivery_log_parses_naive_timestamps_as_utc_and_filters_to_active_subscribers():
    page = Path(
        r"C:\Users\fash\Documents\UIP\deploy\sre-frontend\src\app\webhooks\page.tsx"
    ).read_text(encoding="utf-8")

    assert "function parseWebhookTimestamp" in page
    assert "const normalized = /(?:Z|[+-]\\d{2}:\\d{2})$/.test(text) ? text : `${text}Z`;" in page
    assert "fetchWebhookSubscribers().then(setSubscribers).catch(() => {});" in page
    assert "parseWebhookTimestamp(d.timestamp).toLocaleString()" in page
