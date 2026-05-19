"""Thin facade for NOC Turnover — bundles store, resolver, ingestor, scheduler."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from turnover_ingestor import Ingestor
from turnover_resolver import Resolver
from turnover_scheduler import TurnoverScheduler
from turnover_store import TurnoverStore
from turnover_title_summarizer import TitleSummarizer
from user_name_resolver import UserNameResolver

logger = logging.getLogger(__name__)


class TurnoverCoordinator:
    def __init__(self, db_path: str, slack_client, occir_client,
                 config, activity, jira_base_url: str,
                 dashboard_url: str, ops_noc_channel_id: str,
                 default_turnover_channel_id: str,
                 ollama_url: str, ollama_model: str,
                 jira_client=None, turnover_ollama_model: str = "",
                 group_cache=None):
        self.store = TurnoverStore(db_path)
        turnover_model = turnover_ollama_model or ollama_model
        self.resolver = Resolver(
            store=self.store, occir_client=occir_client,
            ollama_url=ollama_url, ollama_model=turnover_model,
            activity=activity,
            now_fn=lambda: int(time.time()),
        )
        self.title_summarizer = TitleSummarizer(
            store=self.store, ollama_url=ollama_url, ollama_model=turnover_model,
        )
        self.ingestor = Ingestor(
            store=self.store, slack_client=slack_client,
            resolver=self.resolver,
            ops_noc_channel_id=ops_noc_channel_id,
            title_summarizer=self.title_summarizer,
            jira_client=jira_client,
            ollama_url=ollama_url,
            ollama_model=turnover_model,
            jira_base_url=jira_base_url,
            group_cache=group_cache,
        )
        self.user_names = UserNameResolver(slack_client)
        self.scheduler = TurnoverScheduler(
            store=self.store, slack_client=slack_client,
            resolver=self.resolver, config=config, activity=activity,
            jira_base_url=jira_base_url, dashboard_url=dashboard_url,
            default_channel_id=default_turnover_channel_id,
            user_name_lookup=self.user_names,
        )

    def start(self) -> None:
        self.title_summarizer.start()
        # Backfill any incidents that predate the LLM-title column so the
        # carryover list stops showing the raw truncated alert body.
        pending = self.title_summarizer.backfill()
        if pending:
            logger.info("turnover: queued %d incidents for title summarization",
                        pending)
        self.scheduler.start()

    def snapshot(self) -> dict:
        return self.scheduler.snapshot()

    def refresh_now(self) -> dict:
        return self.scheduler.refresh_now()
