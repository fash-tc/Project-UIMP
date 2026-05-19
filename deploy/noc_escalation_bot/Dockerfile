FROM python:3.12-slim

WORKDIR /app

# tzdata lets $TZ=America/New_York actually work for logging timestamps
# (python:3.12-slim omits /usr/share/zoneinfo by default)
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY grafana_irm.py bot.py jira_cr.py api.py group_cache.py occir_jira.py ticket_reactor.py change_tracker.py \
     alert_qa.py \
     turnover_time.py turnover_store.py turnover_metrics.py turnover_renderer.py \
     turnover_resolver.py turnover_ingestor.py turnover_scheduler.py turnover_coordinator.py \
     user_name_resolver.py turnover_title_summarizer.py bot_message_deleter.py \
     turnover_reporter.py bot_actions.py escalation_classifier.py pending_classification.py p3_prompts.py \
     incident_questionnaire.py \
     incident_channel.py incident_channel_store.py incident_channel_creator.py incident_rca.py \
     ./

# Ops scripts (smoke tests, acceptance gate)
COPY scripts/ ./scripts/

CMD ["python", "-u", "bot.py"]
