"""Background LLM summarizer for NOC incident titles.

Raw Slack alert text is noisy — leading @pings, ticket links, pasted alert
bodies with namespace/pod identifiers. The heuristic title picker yields
something like `Kubernetes: Namespace [default] Pod [whois-api-tdp-…`, which
truncates the meaningful bit.

This module accepts submissions and summarizes each into a terse ≤60-char
title via Ollama on a background worker thread, persisting the result on the
incident row. Renderers read the summary lazily from the DB; until it
arrives, they fall back to the heuristic.
"""

from __future__ import annotations

import logging
import queue
import re
import threading
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_MAX_TITLE_CHARS = 60
_PROMPT = (
    "Summarize this NOC alert into one concise title, max {max_chars} chars. "
    "Output ONLY the title — no quotes, no leading labels, no punctuation "
    "at the end. Focus on the component and the symptom. Ignore @mentions "
    "and ticket numbers.\n\n"
    "Alert text:\n{text}"
)


class TitleSummarizer:
    def __init__(self, store, ollama_url: str, ollama_model: str,
                 max_workers: int = 1, timeout: float = 20.0):
        self._store = store
        self._url = ollama_url.rstrip("/")
        self._model = ollama_model
        self._timeout = timeout
        self._q: "queue.Queue[str]" = queue.Queue()
        self._stop = threading.Event()
        self._workers = [
            threading.Thread(
                target=self._worker_loop, daemon=True,
                name=f"turnover-title-{i}",
            )
            for i in range(max_workers)
        ]

    # --- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        for w in self._workers:
            w.start()

    def submit(self, incident_ts: str) -> None:
        """Enqueue an incident for summarization. Safe to call repeatedly."""
        try:
            self._q.put_nowait(incident_ts)
        except queue.Full:
            logger.warning("turnover_title_summarizer: queue full, dropping %s",
                           incident_ts)

    def backfill(self) -> int:
        """Enqueue every incident that lacks a title_summary. Returns count."""
        pending = self._store.incidents_missing_title_summary()
        for ts in pending:
            self.submit(ts)
        return len(pending)

    # --- worker -------------------------------------------------------------

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                ts = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._summarize_one(ts)
            except Exception:
                logger.exception("turnover_title_summarizer: %s failed", ts)
            finally:
                self._q.task_done()

    def _summarize_one(self, incident_ts: str) -> None:
        inc = self._store.get_incident(incident_ts)
        if inc is None:
            return
        if inc.title_summary:
            return  # already populated by a prior run
        text = (inc.text_preview or "").strip()
        if not text:
            return
        summary = self._call_ollama(text)
        if not summary:
            return
        summary = _sanitize(summary)
        if not summary:
            return
        self._store.update_title_summary(incident_ts, summary)

    def _call_ollama(self, text: str) -> Optional[str]:
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system",
                 "content": "You write short, specific NOC alert titles."},
                {"role": "user",
                 "content": _PROMPT.format(max_chars=_MAX_TITLE_CHARS, text=text)},
            ],
            "stream": False,
        }
        try:
            r = requests.post(f"{self._url}/api/chat", json=payload,
                              timeout=self._timeout)
        except requests.RequestException as e:
            logger.warning("turnover_title_summarizer: Ollama request failed: %s", e)
            return None
        if r.status_code != 200:
            logger.warning("turnover_title_summarizer: Ollama %d: %s",
                           r.status_code, r.text[:200])
            return None
        try:
            return r.json()["message"]["content"]
        except (KeyError, ValueError) as e:
            logger.warning("turnover_title_summarizer: bad response: %s", e)
            return None


_RE_QUOTES = re.compile(r'^["\'`]+|["\'`]+$')
_RE_TRAILING_PUNCT = re.compile(r'[\s.,;:!?—–-]+$')


def _sanitize(raw: str) -> str:
    """Trim the LLM output to a clean single-line title ≤ _MAX_TITLE_CHARS."""
    # First non-empty line only — LLMs sometimes add explanations.
    first = next((ln for ln in raw.splitlines() if ln.strip()), "").strip()
    first = _RE_QUOTES.sub("", first)
    first = _RE_TRAILING_PUNCT.sub("", first).strip()
    if len(first) > _MAX_TITLE_CHARS:
        first = first[:_MAX_TITLE_CHARS].rstrip() + "…"
    return first
