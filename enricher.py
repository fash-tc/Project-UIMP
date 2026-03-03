#!/usr/bin/env python3
"""LLM-powered alert enrichment service.
Polls Keep for new alerts, sends them to Ollama for analysis,
and writes enrichment data back to Keep."""

import json
import time
import os
import logging
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("alert-enricher")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
KEEP_URL = os.environ.get("KEEP_URL", "http://keep-api:8080")
KEEP_API_KEY = os.environ.get("KEEP_API_KEY", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))

# Track which alerts we have already enriched (by fingerprint)
enriched_cache = set()


def keep_request(path, method="GET", data=None):
    """Make a request to the Keep API."""
    url = f"{KEEP_URL}{path}"
    body = json.dumps(data).encode() if data else None
    req = Request(url, data=body, method=method, headers={
        "X-API-KEY": KEEP_API_KEY,
        "Content-Type": "application/json",
    })
    try:
        resp = urlopen(req, timeout=30)
        raw = resp.read()
        return json.loads(raw) if raw else {}
    except HTTPError as e:
        if e.code == 404:
            return None
        body_text = ""
        try:
            body_text = e.read().decode()[:200]
        except Exception:
            pass
        log.error(f"Keep API error {e.code} on {method} {path}: {body_text}")
        return None
    except Exception as e:
        log.error(f"Keep request failed: {e}")
        return None


def ollama_generate(prompt, timeout=120):
    """Call Ollama generate API."""
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 512,
        },
    }).encode()
    req = Request(
        f"{OLLAMA_URL}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urlopen(req, timeout=timeout)
        data = json.loads(resp.read())
        return data.get("response", "").strip()
    except Exception as e:
        log.error(f"Ollama error: {e}")
        return None


def wait_for_ollama():
    """Wait for Ollama to be ready and model to be loaded."""
    log.info(f"Waiting for Ollama at {OLLAMA_URL}...")
    for attempt in range(60):
        try:
            resp = urlopen(f"{OLLAMA_URL}/api/tags", timeout=5)
            data = json.loads(resp.read())
            models = [m["name"] for m in data.get("models", [])]
            if any(OLLAMA_MODEL in m for m in models):
                log.info(f"Model {OLLAMA_MODEL} is ready")
                return True
            else:
                log.info(f"Available models: {models}. Pulling {OLLAMA_MODEL}...")
                pull_model()
                return True
        except Exception:
            pass
        time.sleep(10)
    log.error("Ollama not available after 10 minutes")
    return False


def pull_model():
    """Pull the model if not present."""
    log.info(f"Pulling model {OLLAMA_MODEL} (this may take a few minutes)...")
    body = json.dumps({"name": OLLAMA_MODEL, "stream": False}).encode()
    req = Request(
        f"{OLLAMA_URL}/api/pull",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urlopen(req, timeout=600)
        log.info(f"Model pull complete: {resp.read().decode()[:200]}")
    except Exception as e:
        log.error(f"Model pull failed: {e}")


def build_enrichment_prompt(alert):
    """Build the LLM prompt for alert analysis."""
    name = alert.get("name", "Unknown")
    severity = alert.get("severity", "unknown")
    status = alert.get("status", "unknown")
    host = alert.get("hostName", "") or alert.get("hostname", "") or "unknown"
    description = alert.get("description", "") or name
    source = alert.get("source", [])
    tags = alert.get("tags", [])
    last_received = alert.get("lastReceived", "")

    tag_str = ", ".join(
        f"{t.get('tag', t.get('name', ''))}: {t.get('value', '')}"
        for t in (tags if isinstance(tags, list) else [])
    ) or "none"

    source_str = ", ".join(source) if isinstance(source, list) else str(source)

    return (
        "You are an SRE alert analyst for a domain registrar (Tucows Domains). "
        "Analyze this infrastructure alert and provide a brief assessment.\n\n"
        f"ALERT:\n"
        f"- Name: {name}\n"
        f"- Severity: {severity}\n"
        f"- Status: {status}\n"
        f"- Host: {host}\n"
        f"- Description: {description}\n"
        f"- Source: {source_str}\n"
        f"- Tags: {tag_str}\n"
        f"- Time: {last_received}\n\n"
        "Respond in this exact format (keep each field to 1-2 sentences max):\n\n"
        "ASSESSED_SEVERITY: [critical/high/warning/low/info]\n"
        "LIKELY_CAUSE: [brief root cause hypothesis]\n"
        "REMEDIATION: [specific action to investigate or fix]\n"
        "NOISE_SCORE: [1-10, where 1=definitely actionable, 10=likely noise]\n"
        "SUMMARY: [one-line plain English summary for on-call engineer]"
    )


def parse_enrichment(response):
    """Parse the LLM response into structured enrichment data."""
    enrichment = {
        "assessed_severity": "unknown",
        "likely_cause": "",
        "remediation": "",
        "noise_score": 5,
        "summary": "",
    }

    for line in response.split("\n"):
        line = line.strip()
        if line.startswith("ASSESSED_SEVERITY:"):
            val = line.split(":", 1)[1].strip().lower()
            if val in ("critical", "high", "warning", "low", "info"):
                enrichment["assessed_severity"] = val
        elif line.startswith("LIKELY_CAUSE:"):
            enrichment["likely_cause"] = line.split(":", 1)[1].strip()
        elif line.startswith("REMEDIATION:"):
            enrichment["remediation"] = line.split(":", 1)[1].strip()
        elif line.startswith("NOISE_SCORE:"):
            try:
                raw = line.split(":", 1)[1].strip()
                score = int(raw.split("/")[0].split(" ")[0])
                enrichment["noise_score"] = max(1, min(10, score))
            except (ValueError, IndexError):
                pass
        elif line.startswith("SUMMARY:"):
            enrichment["summary"] = line.split(":", 1)[1].strip()

    return enrichment


def enrich_alert(alert):
    """Send an alert to the LLM and return enrichment data."""
    prompt = build_enrichment_prompt(alert)
    response = ollama_generate(prompt)
    if not response:
        return None

    enrichment = parse_enrichment(response)
    enrichment["llm_model"] = OLLAMA_MODEL
    enrichment["llm_raw_response"] = response
    return enrichment


def post_enrichment_to_keep(alert, enrichment):
    """Write enrichment data back to Keep."""
    fingerprint = alert.get("fingerprint", "")
    if not fingerprint:
        return False

    note = (
        f"AI Summary: {enrichment['summary']}\n"
        f"Likely Cause: {enrichment['likely_cause']}\n"
        f"Remediation: {enrichment['remediation']}"
    )

    # Use the note enrichment endpoint — renders at the top of the alert detail
    result = keep_request(
        "/alerts/enrich/note",
        method="POST",
        data={"fingerprint": fingerprint, "note": note},
    )
    if result is not None:
        return True

    log.warning(f"Enrichment POST failed for {fingerprint[:16]}")
    return False


def poll_and_enrich():
    """Poll Keep for new alerts and enrich them."""
    alerts_data = keep_request("/alerts?limit=50")
    if not alerts_data:
        return 0

    items = (
        alerts_data.get("items", alerts_data)
        if isinstance(alerts_data, dict)
        else alerts_data
    )
    if not isinstance(items, list):
        return 0

    enriched_count = 0
    for alert in items:
        fingerprint = alert.get("fingerprint", "")
        if not fingerprint or fingerprint in enriched_cache:
            continue
        # Skip alerts already enriched (survives service restarts)
        note = alert.get("note", "") or ""
        if note.startswith("AI Summary:"):
            enriched_cache.add(fingerprint)
            continue

        name = alert.get("name", "unknown")
        log.info(f"Enriching: {name[:60]} (fp: {fingerprint[:16]}...)")

        enrichment = enrich_alert(alert)
        if enrichment:
            success = post_enrichment_to_keep(alert, enrichment)
            if success:
                enriched_cache.add(fingerprint)
                enriched_count += 1
                log.info(
                    f"  -> severity={enrichment['assessed_severity']} "
                    f"noise={enrichment['noise_score']}/10 "
                    f"| {enrichment['summary'][:60]}"
                )
            else:
                log.warning("  -> Failed to post enrichment to Keep")
        else:
            log.warning("  -> LLM returned no response")

    return enriched_count


def main():
    log.info("Starting LLM Alert Enrichment Service")
    log.info(f"Ollama: {OLLAMA_URL} | Model: {OLLAMA_MODEL}")
    log.info(f"Keep: {KEEP_URL} | Poll interval: {POLL_INTERVAL}s")

    if not wait_for_ollama():
        log.error("Cannot start without Ollama. Exiting.")
        return

    # Test LLM with a simple prompt
    log.info("Testing LLM connectivity...")
    test = ollama_generate("Say 'ready' if you can process alerts.")
    if test:
        log.info(f"LLM test: {test[:100]}")
    else:
        log.warning("LLM test failed, will retry during enrichment")

    while True:
        try:
            count = poll_and_enrich()
            if count > 0:
                log.info(f"Enriched {count} alerts this cycle")
        except Exception as e:
            log.error(f"Enrichment cycle failed: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
