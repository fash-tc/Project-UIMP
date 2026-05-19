"""Pure aggregate functions over incidents. No I/O."""

from __future__ import annotations

import statistics
from typing import Optional

from turnover_store import Incident


def compute_metrics(
    incidents: list[Incident],
    window_start: int,
    window_end: int,
    threshold_minutes: int,
) -> dict:
    """Compute the MetricsBundle for a given list of incidents.

    Returns a dict with keys documented in the spec. `None` where no
    qualifying rows exist (do not return 0 — it means 'no data', not 'zero').
    """
    total = len(incidents)
    resolved_list = [i for i in incidents if i.resolved_at is not None]
    open_count = total - len(resolved_list)

    replied = [i for i in incidents if i.first_reply_at is not None]
    ack_secs = [i.first_reply_at - i.posted_at for i in replied]

    threshold_sec = threshold_minutes * 60

    median_ack = statistics.median(ack_secs) if ack_secs else None
    pct_acked = (
        sum(1 for s in ack_secs if s <= threshold_sec) / len(ack_secs)
        if ack_secs else None
    )

    avg_replies = (
        sum(i.reply_count for i in incidents) / total
        if total else None
    )

    mttr_secs = [i.resolved_at - i.posted_at for i in resolved_list]
    mttr_median = statistics.median(mttr_secs) if mttr_secs else None

    return {
        "window": "window",
        "window_start": window_start,
        "window_end": window_end,
        "total": total,
        "open": open_count,
        "resolved": len(resolved_list),
        "median_ack_seconds": median_ack,
        "pct_acked_within_threshold": pct_acked,
        "threshold_minutes": threshold_minutes,
        "avg_replies": avg_replies,
        "mttr_seconds": mttr_median,
    }
