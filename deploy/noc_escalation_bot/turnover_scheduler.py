"""Daemon-thread scheduler for NOC Turnover shift posts + refresh ticks."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from inspect import Parameter, signature
from typing import Callable, Optional

from turnover_store import TurnoverStore, ShiftPost
from turnover_time import (
    ET, shift_key_for, compute_shift_window,
    next_shift_boundary, next_refresh_tick,
)
from turnover_renderer import render_shift_post
from turnover_metrics import compute_metrics

logger = logging.getLogger(__name__)

STALE_OPEN_SECONDS = 2 * 24 * 3600
STALE_OPEN_DISMISS_BY = "system:turnover"
STALE_OPEN_DISMISS_REASON = "auto-cleared from turnover queue: older than 2 days"


@dataclass(frozen=True)
class SweepSummary:
    checked: int
    auto_resolved: int
    still_open: int
    errors: int
    ran_at: int
    source: str


class TurnoverScheduler:
    def __init__(self, store: TurnoverStore, slack_client, resolver,
                 config, activity, jira_base_url: str, dashboard_url: str,
                 default_channel_id: str,
                 user_name_lookup: Optional[Callable[[str], str]] = None,
                 now_fn: Optional[Callable[[], datetime]] = None):
        self._store = store
        self._slack = slack_client
        self._resolver = resolver
        self._config = config
        self._activity = activity
        self._jira_base_url = jira_base_url
        self._dashboard_url = dashboard_url
        self._default_channel = default_channel_id
        self._user_name = user_name_lookup or _noop_user_lookup
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self._thread: Optional[threading.Thread] = None
        self._last_step_ts: Optional[datetime] = None
        self._next_wake_ts: Optional[datetime] = None
        self._shift_locks: dict[str, threading.Lock] = {}
        self._shift_locks_guard = threading.Lock()

    def refresh_now(self) -> dict:
        """Force-refresh + backfill any missed shift boundaries.

        Synchronous: runs in the caller's thread, independent of the scheduler
        loop. First backfills any shift boundaries in the last 24h that have no
        corresponding post (e.g. missed due to a redeploy crossing the tick),
        then refreshes every currently-active shift post.
        """
        now = self._now()
        cfg = self._config.get_all()
        if not cfg.get("noc_turnover_enabled", True):
            return {"updated": 0, "posted": 0, "skipped_reason": "disabled"}
        sweep_summary = self._run_resolve_sweep(source="manual_refresh")

        # Backfill missed shift boundaries in the past 24h.
        posted: list[str] = []
        for fire_utc in self._recent_shift_boundaries(now, lookback_hours=24):
            fire_et = fire_utc.astimezone(ET)
            shift_key = shift_key_for(fire_et)
            if self._store.get_shift_post(shift_key) is None:
                self._handle_shift_boundary(fire_utc, cfg, sweep_summary=sweep_summary)
                if self._store.get_shift_post(shift_key) is not None:
                    posted.append(shift_key)

        active = self._store.active_shift_posts(int(now.timestamp()))
        for sp in active:
            self._update_existing_post(sp, cfg, now, sweep_summary=sweep_summary)
        self._last_step_ts = now
        return {
            "updated": len(active),
            "posted": posted,
            "at": now.isoformat(),
        }

    def _recent_shift_boundaries(self, now: datetime, lookback_hours: int = 24):
        """Yield shift-fire UTC datetimes in [now - lookback, now], ascending."""
        cutoff = now - timedelta(hours=lookback_hours)
        now_et = now.astimezone(ET)
        scan_start_et = (now_et - timedelta(hours=lookback_hours + 24)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        out = []
        cursor = scan_start_et
        while cursor <= now_et:
            for h in (0, 9, 17):
                fire_et = cursor.replace(hour=h, minute=0, second=0, microsecond=0)
                fire_utc = fire_et.astimezone(timezone.utc)
                if cutoff <= fire_utc <= now:
                    out.append(fire_utc)
            cursor = cursor + timedelta(days=1)
        return sorted(out)

    def snapshot(self) -> dict:
        now_utc = self._now()
        active = self._store.active_shift_posts(int(now_utc.timestamp()))
        active_key = active[-1].shift_key if active else None
        open_count = len(self._store.get_open_incidents())
        return {
            "last_refresh_ts": self._last_step_ts.isoformat() if self._last_step_ts else None,
            "next_refresh_ts": self._next_wake_ts.isoformat() if self._next_wake_ts else None,
            "active_shift_key": active_key,
            "open_count": open_count,
        }

    # --- per-shift locking + rerender ---------------------------------------

    def _lock_for(self, shift_key: str) -> threading.Lock:
        with self._shift_locks_guard:
            lk = self._shift_locks.get(shift_key)
            if lk is None:
                lk = threading.Lock()
                self._shift_locks[shift_key] = lk
            return lk

    def rerender(self, shift_key: str, sweep_summary: Optional[SweepSummary] = None) -> None:
        """Re-render the turnover post for `shift_key` from current store state.

        Single entry point for all in-place updates — both the scheduled
        refresh tick and every button handler route through here, under a
        per-shift lock, so concurrent updates don't clobber each other."""
        with self._lock_for(shift_key):
            sp = self._store.get_shift_post(shift_key)
            if sp is None:
                return
            cfg = self._config.get_all()
            text, blocks = self._build_body(
                sp.shift_key, sp.window_start, sp.window_end,
                cfg, datetime.now(timezone.utc),
                sweep_summary=sweep_summary,
            )
            try:
                self._slack.chat_update(
                    channel=sp.channel_id, ts=sp.message_ts,
                    text=text, blocks=blocks,
                    unfurl_links=False, unfurl_media=False,
                )
            except Exception as e:
                err_code = None
                resp = getattr(e, "response", None)
                if isinstance(resp, dict):
                    err_code = resp.get("error")
                if err_code == "message_not_found":
                    logger.warning("turnover_scheduler: %s message missing — deleting row",
                                    sp.shift_key)
                    self._store.delete_shift_post(sp.shift_key)
                    return
                logger.warning("turnover_scheduler: chat_update failed for %s: %s",
                                sp.shift_key, e)
                return
            self._store.touch_shift_post(
                sp.shift_key, int(datetime.now(timezone.utc).timestamp()),
            )

    def refresh_shift(self, shift_key: str) -> None:
        """Run a resolve sweep, then re-render the requested shift post."""
        if self._store.get_shift_post(shift_key) is None:
            return
        sweep_summary = self._run_resolve_sweep(source="slack_refresh")
        self.rerender(shift_key, sweep_summary=sweep_summary)

    # --- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                         name="turnover-scheduler")
        self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                now = self._now()
                reason, fire_time = self._next_wake(now)
                self._next_wake_ts = fire_time
                delay = max(0.0, (fire_time - now).total_seconds())
                time.sleep(delay)
                self._step(reason=reason, fire_time=fire_time)
            except Exception:
                logger.exception("turnover_scheduler: step crashed, continuing")
                time.sleep(5)

    # --- wake planning ------------------------------------------------------

    def _next_wake(self, now: datetime) -> tuple[str, datetime]:
        """Return (reason, fire_time). Shift boundary wins ties."""
        nxt_shift = next_shift_boundary(now).astimezone(timezone.utc)
        nxt_tick = next_refresh_tick(now)
        if nxt_shift <= nxt_tick:
            return "shift", nxt_shift
        return "refresh", nxt_tick

    # --- single step --------------------------------------------------------

    def _step(self, reason: str, fire_time: datetime) -> None:
        self._last_step_ts = fire_time
        cfg = self._config.get_all()
        if not cfg.get("noc_turnover_enabled", True):
            return

        sweep_summary = self._run_resolve_sweep(source=reason)

        if reason == "shift":
            self._handle_shift_boundary(fire_time, cfg, sweep_summary=sweep_summary)
        else:
            self._handle_refresh_tick(fire_time, cfg, sweep_summary=sweep_summary)

    def _run_resolve_sweep(self, *, source: str) -> SweepSummary:
        before = {i.slack_ts for i in self._store.get_open_incidents()}
        ran_at = int(self._now().timestamp())
        try:
            self._resolver.sweep()
        except Exception:
            logger.warning("turnover_scheduler: resolve sweep failed", exc_info=True)
            return SweepSummary(
                checked=len(before),
                auto_resolved=0,
                still_open=len(before),
                errors=len(before),
                ran_at=ran_at,
                source=source,
            )
        after = {i.slack_ts for i in self._store.get_open_incidents()}
        return SweepSummary(
            checked=len(before),
            auto_resolved=len(before - after),
            still_open=len(after),
            errors=0,
            ran_at=ran_at,
            source=source,
        )

    def _handle_shift_boundary(self, fire_time_utc: datetime, cfg: dict,
                               sweep_summary: Optional[SweepSummary] = None) -> None:
        fire_et = fire_time_utc.astimezone(ET)
        shift_key = shift_key_for(fire_et)
        win_start_utc, win_end_utc = compute_shift_window(fire_et)
        win_start = int(win_start_utc.timestamp())
        win_end = int(win_end_utc.timestamp())
        channel = cfg.get("noc_turnover_channel_id") or self._default_channel

        existing = self._store.get_shift_post(shift_key)
        if existing:
            # Cold-start replay: edit existing message instead of reposting
            self._update_existing_post(
                existing, cfg, fire_time_utc, sweep_summary=sweep_summary,
            )
            return

        text, blocks = self._build_body(
            shift_key, win_start, win_end, cfg, fire_time_utc,
            sweep_summary=sweep_summary,
        )
        try:
            resp = self._slack.chat_postMessage(
                channel=channel, text=text, blocks=blocks,
                unfurl_links=False, unfurl_media=False,
            )
            message_ts = resp["ts"] if isinstance(resp, dict) else str(resp.get("ts"))
        except Exception as e:
            logger.error("turnover_scheduler: chat_postMessage failed: %s", e)
            return

        slot = shift_key.rsplit("-", 1)[-1]
        self._store.record_shift_post(ShiftPost(
            shift_key=shift_key, slot=slot,
            window_start=win_start, window_end=win_end,
            channel_id=channel, message_ts=message_ts,
            posted_at=int(fire_time_utc.timestamp()),
            last_updated_at=int(fire_time_utc.timestamp()),
        ))
        self._activity.add("turnover_posted", shift_key)

    def _handle_refresh_tick(self, fire_time_utc: datetime, cfg: dict,
                             sweep_summary: Optional[SweepSummary] = None) -> None:
        now_sec = int(fire_time_utc.timestamp())
        for sp in self._store.active_shift_posts(now_sec):
            self._update_existing_post(
                sp, cfg, fire_time_utc, sweep_summary=sweep_summary,
            )

    def _update_existing_post(self, sp: ShiftPost, cfg: dict,
                              fire_time_utc: datetime,
                              sweep_summary: Optional[SweepSummary] = None) -> None:
        self.rerender(sp.shift_key, sweep_summary=sweep_summary)

    # --- body construction --------------------------------------------------

    def _build_body(self, shift_key: str, win_start: int, win_end: int,
                    cfg: dict, fire_time_utc: datetime,
                    sweep_summary: Optional[SweepSummary] = None) -> tuple[str, list[dict]]:
        self._dismiss_stale_open_incidents(fire_time_utc)
        in_window = self._store.get_incidents_in_window(win_start, win_end)
        all_open = self._store.get_open_incidents()
        in_window_ts = {i.slack_ts for i in in_window}
        carryover = [i for i in all_open if i.slack_ts not in in_window_ts]
        for incident in in_window:
            self._store.mark_seen_in_shift(
                incident.slack_ts, shift_key=shift_key, is_carryover=False,
            )
        for incident in carryover:
            self._store.mark_seen_in_shift(
                incident.slack_ts, shift_key=shift_key, is_carryover=True,
            )
        metrics = compute_metrics(
            in_window, win_start, win_end,
            threshold_minutes=int(cfg.get("noc_turnover_ack_threshold_min", 15)),
        )
        next_tick = next_refresh_tick(fire_time_utc)

        handoff_items = self._store.get_handoff_items(shift_key)

        kwargs = dict(
            shift_key=shift_key,
            window_start=win_start, window_end=win_end,
            incidents_in_window=in_window,
            carryover_incidents=carryover,
            handoff_items=handoff_items,
            last_reply_lookup=self._store.last_reply,
            unique_responder_lookup=self._store.unique_responder_count,
            metrics=metrics,
            user_name_lookup=self._user_name,
            now_utc=fire_time_utc,
            next_refresh_utc=next_tick,
            jira_base_url=self._jira_base_url,
            dashboard_url=self._dashboard_url,
        )
        render_params = signature(render_shift_post).parameters
        if (
            "sweep_summary" in render_params
            or any(p.kind == Parameter.VAR_KEYWORD for p in render_params.values())
        ):
            kwargs["sweep_summary"] = sweep_summary
        return render_shift_post(**kwargs)

    def _dismiss_stale_open_incidents(self, now_utc: datetime) -> int:
        now_sec = int(now_utc.timestamp())
        cutoff = now_sec - STALE_OPEN_SECONDS
        dismissed = self._store.dismiss_open_incidents_older_than(
            cutoff,
            at=now_sec,
            by_user_id=STALE_OPEN_DISMISS_BY,
            reason=STALE_OPEN_DISMISS_REASON,
        )
        if dismissed:
            logger.info(
                "turnover_scheduler: auto-dismissed %d stale open incidents older than 2 days",
                dismissed,
            )
        return dismissed


def _noop_user_lookup(user_id: str) -> str:
    return user_id
