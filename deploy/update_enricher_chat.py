#!/usr/bin/env python3
"""Update enricher.py on server: switch from /api/generate to /api/chat,
remove system prompt from build_enrichment_prompt (now baked into qwen-tooling Modelfile)."""
import re

ENRICHER_PATH = "/home/fash/uip/enricher/enricher.py"

with open(ENRICHER_PATH, "r") as f:
    code = f.read()

# 1. Replace ollama_generate to use /api/chat with user message only
old_generate = '''def ollama_generate(prompt, timeout=45):
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "think": False,
        "options": {
            "num_predict": 1024,
        },
    }).encode()
    req = Request(
        f"{OLLAMA_URL}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    for attempt in range(2):
        try:
            resp = urlopen(req, timeout=timeout)
            data = json.loads(resp.read())
            return data.get("response", "").strip()
        except Exception as e:
            if attempt == 0:
                log.warning(f"Ollama timeout/error (attempt 1), retrying: {e}")
                time.sleep(2)
            else:
                log.error(f"Ollama failed after 2 attempts: {e}")
    return None'''

new_generate = '''def ollama_generate(prompt, timeout=45):
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": "json",
        "think": False,
        "options": {
            "num_predict": 1024,
        },
    }).encode()
    req = Request(
        f"{OLLAMA_URL}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    for attempt in range(2):
        try:
            resp = urlopen(req, timeout=timeout)
            data = json.loads(resp.read())
            msg = data.get("message", {})
            return msg.get("content", "").strip()
        except Exception as e:
            if attempt == 0:
                log.warning(f"Ollama timeout/error (attempt 1), retrying: {e}")
                time.sleep(2)
            else:
                log.error(f"Ollama failed after 2 attempts: {e}")
    return None'''

if old_generate in code:
    code = code.replace(old_generate, new_generate)
    print("OK: Replaced ollama_generate to use /api/chat")
else:
    print("WARN: Could not find exact ollama_generate match")

# 2. Replace the system prompt preamble in build_enrichment_prompt
# Remove the big SRE principles block and just send alert data + context
old_return_start = '''    return (
        "You are a senior SRE alert analyst for Tucows Domains, a major domain "
        "registrar operating critical DNS, EPP, WHOIS, and billing infrastructure "
        "across OpenSRS, Ascio, Enom, and Tucows Registry Services platforms.\\n\\n"
        "Apply Google SRE principles in your analysis:\\n"
        "- FOCUS ON USER IMPACT: Assess whether real users (registrars, domain owners, "
        "partners) are affected. An alert without user-facing impact is lower priority "
        "regardless of the internal metric's raw value.\\n"
        "- FOUR GOLDEN SIGNALS: Consider which signal this alert relates to "
        "(Latency, Traffic, Errors, Saturation). Saturation alerts (CPU, memory, disk) "
        "are early warnings — assess how close the resource is to hard limits and whether "
        "it is actively degrading user-facing SLIs.\\n"
        "- SYMPTOMS vs CAUSES: Distinguish what is broken (the symptom users see) from "
        "why it is broken (the underlying cause). Frame your analysis around the symptom.\\n"
        "- TRIAGE FIRST: Prioritize mitigation (restore service) over root-cause analysis. "
        "Remediation steps should focus on stopping the bleeding first, then investigating.\\n"
        "- WHAT CHANGED: Consider recent deployments, config changes, traffic shifts, or "
        "upstream failures as likely triggers. Systems maintain inertia — something changed.\\n"
        "- CORRELATION vs CAUSATION: If similar alerts exist, determine whether they share "
        "a root cause or are coincidental. Shared infrastructure (same host, same rack, "
        "same service) increases the probability of a common cause.\\n"
        "- ACTIONABILITY: Every page should require human intelligence to resolve. If this "
        "alert would auto-resolve, is flapping, or requires no human action, it is noise.\\n"
        "- ERROR BUDGET THINKING: Frame severity by how much this eats into the service's "
        "reliability budget. A brief CPU spike on a redundant DNS node is very different "
        "from sustained saturation on a single-point-of-failure database.\\n\\n"
        f"ALERT:\\n"'''

new_return_start = '''    return (
        f"ALERT:\\n"'''

if old_return_start in code:
    code = code.replace(old_return_start, new_return_start)
    print("OK: Removed system prompt preamble from build_enrichment_prompt")
else:
    print("WARN: Could not find exact system prompt preamble")

# 3. Remove the output schema instructions (now in Modelfile SYSTEM)
old_schema = '''        "Respond with a JSON object containing exactly these fields (keep values concise, 1-3 sentences):\\n"
        '{"assessed_severity": "critical|high|warning|low|info",\\n'
        '"likely_cause": "root cause hypothesis",\\n'
        '"remediation": "concrete triage-first steps for on-call",\\n'
        '"impact_scope": "affected services/users, SLIs at risk, blast radius",\\n'
        '"dedup_assessment": "DUPLICATE|CORRELATED|UNIQUE",\\n'
        '"dedup_reason": "brief explanation",\\n'
        '"noise_score": 1,\\n'
        '"noise_reason": "why this score",\\n'
        '"summary": "one-line for on-call, lead with user impact"}\\n'
        "Rules: assessed_severity must be one of critical/high/warning/low/info. "
        "noise_score must be integer 1-10 (1=actionable, 10=noise). "
        "dedup_assessment must be DUPLICATE, CORRELATED, or UNIQUE.\\n"'''

new_schema = '''        "Analyze this alert and respond with the required JSON.\\n"'''

if old_schema in code:
    code = code.replace(old_schema, new_schema)
    print("OK: Replaced inline schema with short instruction")
else:
    print("WARN: Could not find exact schema block")

with open(ENRICHER_PATH, "w") as f:
    f.write(code)

print("\nDone. Enricher updated to use /api/chat with Modelfile system prompt.")
