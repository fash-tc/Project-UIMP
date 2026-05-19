"""Time helpers for NOC Turnover — pure, DST-aware, no I/O.

Shift-post fires at 00:00 / 09:00 / 17:00 America/New_York. Each post covers
the shift that is ABOUT TO BEGIN (prospective) — the window ahead of the
fire time. Incidents still open from the prior shift show up in the
renderer's carryover ("open from earlier") section. Refresh ticks land on
:00 / :30 UTC.
"""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")

SHIFT_HOURS = (0, 9, 17)  # ET hours at which shift posts fire

_SLOT_WINDOWS = {
    "overnight": (0, 9),
    "morning":   (9, 17),
    "evening":   (17, 24),
}


def _slot_for_fire_hour(hour_et: int) -> str:
    if hour_et == 0:
        return "overnight"
    if hour_et == 9:
        return "morning"
    if hour_et == 17:
        return "evening"
    raise ValueError(f"Not a shift fire hour: {hour_et}")


def shift_key_for(fire_time_et: datetime) -> str:
    """Given a shift-fire datetime in ET, return the shift_key it represents.

    The fire at the START of a shift names that shift:
      00:00 → overnight (00:00–09:00)
      09:00 → morning   (09:00–17:00)
      17:00 → evening   (17:00–24:00)
    All three use the current ET date.
    """
    if fire_time_et.tzinfo is None:
        raise ValueError("fire_time_et must be tz-aware")
    fire_et = fire_time_et.astimezone(ET)
    slot = _slot_for_fire_hour(fire_et.hour)
    return f"{fire_et.date().isoformat()}-{slot}"


def compute_shift_window(fire_time_et: datetime) -> tuple[datetime, datetime]:
    """Return (start_utc, end_utc) for the shift the given fire covers.

    Prospective: start = fire time, end = next boundary."""
    if fire_time_et.tzinfo is None:
        raise ValueError("fire_time_et must be tz-aware")
    fire_et = fire_time_et.astimezone(ET)
    slot = _slot_for_fire_hour(fire_et.hour)
    start_hour, end_hour = _SLOT_WINDOWS[slot]
    base = fire_et.replace(hour=0, minute=0, second=0, microsecond=0)
    start = base.replace(hour=start_hour)
    end = base.replace(hour=end_hour) if end_hour < 24 else base + timedelta(days=1)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def next_shift_boundary(now: datetime) -> datetime:
    """Return the next 00/09/17 ET datetime strictly after `now`."""
    if now.tzinfo is None:
        raise ValueError("now must be tz-aware")
    now_et = now.astimezone(ET)
    today_candidates = [
        now_et.replace(hour=h, minute=0, second=0, microsecond=0)
        for h in SHIFT_HOURS
    ]
    for candidate in today_candidates:
        if candidate > now_et:
            return candidate
    tomorrow = (now_et + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return tomorrow


def next_refresh_tick(now: datetime) -> datetime:
    """Return the next :00 or :30 UTC datetime strictly after `now`."""
    if now.tzinfo is None:
        raise ValueError("now must be tz-aware")
    now_utc = now.astimezone(timezone.utc)
    base = now_utc.replace(second=0, microsecond=0)
    if base.minute < 30:
        return base.replace(minute=30)
    return (base + timedelta(hours=1)).replace(minute=0)
