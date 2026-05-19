#!/bin/sh
# Uptime watchdog for the NOC Escalation Bot.
#
# Runs forever. Every $INTERVAL seconds it hits the bot's /status endpoint
# (via the shared docker network — no host ports needed). After
# $FAILURES consecutive failures, it DMs $ALERT_USER_ID via Slack and
# enters a cooldown so it doesn't spam.
#
# This runs on the server, not the laptop, so it stays online when the
# operator's VPN drops.

set -eu

URL="${STATUS_URL:-http://noc-escalation-bot:8095/status}"
INTERVAL="${INTERVAL_SEC:-60}"
FAILURES="${FAILURE_THRESHOLD:-3}"
COOLDOWN="${ALERT_COOLDOWN_SEC:-1800}"   # 30 min between alerts
ALERT_USER_ID="${ALERT_USER_ID:?ALERT_USER_ID required}"
SLACK_BOT_TOKEN="${SLACK_BOT_TOKEN:?SLACK_BOT_TOKEN required}"

consecutive=0
last_alert=0
last_state="up"

dm_alert() {
    text="$1"
    # Open IM with the user, then post the message into that channel.
    channel=$(curl -sS -X POST https://slack.com/api/conversations.open \
        -H "Authorization: Bearer ${SLACK_BOT_TOKEN}" \
        -H "Content-type: application/json; charset=utf-8" \
        --data "{\"users\":\"${ALERT_USER_ID}\"}" \
        | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -n1)
    if [ -z "${channel}" ]; then
        echo "$(date -u +%FT%TZ) ERROR: conversations.open returned no id"
        return 1
    fi
    curl -sS -X POST https://slack.com/api/chat.postMessage \
        -H "Authorization: Bearer ${SLACK_BOT_TOKEN}" \
        -H "Content-type: application/json; charset=utf-8" \
        --data "$(printf '{"channel":"%s","text":%s}' "${channel}" \
                  "$(printf '%s' "${text}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')")" \
        >/dev/null
}

echo "$(date -u +%FT%TZ) watchdog start: url=${URL} interval=${INTERVAL}s threshold=${FAILURES}"

while :; do
    if curl -sf -m 10 -o /dev/null "${URL}"; then
        if [ "${last_state}" = "down" ]; then
            echo "$(date -u +%FT%TZ) recovered after ${consecutive} failures"
            dm_alert ":white_check_mark: NOC bot /status recovered." || true
        fi
        consecutive=0
        last_state="up"
    else
        consecutive=$((consecutive + 1))
        echo "$(date -u +%FT%TZ) probe failed (consecutive=${consecutive})"
        if [ "${consecutive}" -ge "${FAILURES}" ]; then
            now=$(date +%s)
            since=$((now - last_alert))
            if [ "${since}" -ge "${COOLDOWN}" ]; then
                echo "$(date -u +%FT%TZ) firing alert"
                if dm_alert ":rotating_light: NOC bot /status has failed ${consecutive} times in a row at ${URL}. Container may be stuck — check Portainer or \`docker logs uip-noc-escalation-bot-1\`."; then
                    last_alert="${now}"
                fi
            fi
            last_state="down"
        fi
    fi
    sleep "${INTERVAL}"
done
