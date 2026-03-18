#!/usr/bin/env python3
"""Add /ai-chat-api/ proxy to nginx config for Open WebUI iframe embedding."""

import sys

CONF_PATH = sys.argv[1] if len(sys.argv) > 1 else "/home/fash/uip/nginx/default.conf"

with open(CONF_PATH) as f:
    content = f.read()

if "/ai-chat-api/" in content:
    print("ai-chat-api location already exists, skipping")
    sys.exit(0)

# The block to add — proxies /ai-chat-api/ to Open WebUI with WebSocket support
AI_CHAT_BLOCK = """
    # AI Chat — Open WebUI iframe proxy
    location /ai-chat-api/ {
        proxy_pass http://open-webui:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_read_timeout 86400s;
    }

"""

# Insert before the first location block in the main server
# Find "location / {" or "location /portal" — insert before it
insert_marker = "    # Alert State API"
if insert_marker not in content:
    # Try another marker
    insert_marker = "    location / {"
    if insert_marker not in content:
        print("ERROR: Could not find insertion point in nginx config")
        sys.exit(1)

content = content.replace(insert_marker, AI_CHAT_BLOCK + insert_marker, 1)

with open(CONF_PATH, "w") as f:
    f.write(content)

print(f"Added /ai-chat-api/ proxy block to {CONF_PATH}")
