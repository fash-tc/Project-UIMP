#!/usr/bin/env python3
"""Patch enricher.py to use JSON mode with qwen-tooling."""
import re

with open("/home/fash/uip/enricher/enricher.py", "r") as f:
    content = f.read()

# 1. Update ollama_generate: add format=json, think=False, remove hardcoded temperature
content = content.replace(
    '"prompt": prompt,\n        "stream": False,\n        "options": {\n            "temperature": 0.3,\n            "num_predict": 768,\n        },',
    '"prompt": prompt,\n        "stream": False,\n        "format": "json",\n        "think": False,\n        "options": {\n            "num_predict": 1024,\n        },'
)

# 2. Replace the text-format prompt ending with JSON schema request
old_prompt = (
    '"Respond in this EXACT format. Keep each field concise (1-3 sentences max):\\n\\n"\n'
)
# Find from "Respond in this EXACT format" to the closing ");\n" of the return statement
pattern = re.compile(
    r'"Respond in this EXACT format\. Keep each field concise.*?'
    r'"then the technical detail\.\]\\n"\s*\)',
    re.DOTALL,
)
replacement = (
    '"Respond with a JSON object containing exactly these fields (keep values concise, 1-3 sentences):\\n"\n'
    '        \'{"assessed_severity": "critical|high|warning|low|info",\\n\'\n'
    '        \'"likely_cause": "root cause hypothesis",\\n\'\n'
    '        \'"remediation": "concrete triage-first steps for on-call",\\n\'\n'
    '        \'"impact_scope": "affected services/users, SLIs at risk, blast radius",\\n\'\n'
    '        \'"dedup_assessment": "DUPLICATE|CORRELATED|UNIQUE",\\n\'\n'
    '        \'"dedup_reason": "brief explanation",\\n\'\n'
    '        \'"noise_score": 1,\\n\'\n'
    '        \'"noise_reason": "why this score",\\n\'\n'
    '        \'"summary": "one-line for on-call, lead with user impact"}\\n\'\n'
    '        "Rules: assessed_severity must be one of critical/high/warning/low/info. "\n'
    '        "noise_score must be integer 1-10 (1=actionable, 10=noise). "\n'
    '        "dedup_assessment must be DUPLICATE, CORRELATED, or UNIQUE.\\n"\n'
    '    )'
)
content = pattern.sub(replacement, content)

# 3. Replace parse_enrichment with JSON-based parser
old_parse = re.compile(
    r'def parse_enrichment\(response\):.*?return enrichment',
    re.DOTALL,
)
new_parse = '''def parse_enrichment(response):
    """Parse JSON response from qwen-tooling model."""
    defaults = {
        "assessed_severity": "unknown",
        "likely_cause": "",
        "remediation": "",
        "impact_scope": "",
        "dedup_assessment": "UNIQUE",
        "dedup_reason": "",
        "noise_score": 5,
        "noise_reason": "",
        "summary": "",
    }

    # Try JSON parse first (structured output mode)
    try:
        data = json.loads(response)
        enrichment = {}
        for key, default in defaults.items():
            enrichment[key] = data.get(key, default)
        # Validate/normalize fields
        if enrichment["assessed_severity"] not in ("critical", "high", "warning", "low", "info"):
            enrichment["assessed_severity"] = "unknown"
        if isinstance(enrichment["noise_score"], str):
            try:
                enrichment["noise_score"] = int(enrichment["noise_score"])
            except ValueError:
                enrichment["noise_score"] = 5
        enrichment["noise_score"] = max(1, min(10, enrichment["noise_score"]))
        if enrichment["dedup_assessment"] not in ("DUPLICATE", "CORRELATED", "UNIQUE"):
            enrichment["dedup_assessment"] = "UNIQUE"
        return enrichment
    except (json.JSONDecodeError, TypeError):
        log.warning("JSON parse failed, falling back to text parsing")

    # Fallback: text-based parsing for backwards compat
    enrichment = dict(defaults)
    field_map = {
        "ASSESSED_SEVERITY": "assessed_severity",
        "LIKELY_CAUSE": "likely_cause",
        "REMEDIATION": "remediation",
        "IMPACT_SCOPE": "impact_scope",
        "DEDUP_ASSESSMENT": "dedup_assessment",
        "DEDUP_REASON": "dedup_reason",
        "NOISE_SCORE": "noise_score",
        "NOISE_REASON": "noise_reason",
        "SUMMARY": "summary",
    }
    for line in response.split("\\n"):
        line = line.strip()
        for prefix, key in field_map.items():
            if line.upper().startswith(prefix + ":"):
                val = line.split(":", 1)[1].strip()
                if key == "assessed_severity":
                    val = val.lower().strip("[]")
                    if val in ("critical", "high", "warning", "low", "info"):
                        enrichment[key] = val
                elif key == "noise_score":
                    try:
                        score = int(val.strip("[]").split("/")[0].split(" ")[0])
                        enrichment[key] = max(1, min(10, score))
                    except (ValueError, IndexError):
                        pass
                elif key == "dedup_assessment":
                    val_upper = val.upper().strip("[]")
                    if val_upper in ("DUPLICATE", "CORRELATED", "UNIQUE"):
                        enrichment[key] = val_upper
                else:
                    enrichment[key] = val
                break

    if not enrichment["remediation"]:
        enrichment["remediation"] = "1. Check resource utilization. 2. Review recent changes. 3. Escalate if persists."
    if not enrichment["likely_cause"]:
        enrichment["likely_cause"] = "Unable to determine root cause from available context."
    if not enrichment["impact_scope"]:
        enrichment["impact_scope"] = "Impact assessment requires manual investigation."
    if not enrichment["noise_reason"]:
        enrichment["noise_reason"] = "Insufficient context to determine noise level."

    return enrichment'''

content = old_parse.sub(new_parse, content)

with open("/home/fash/uip/enricher/enricher.py", "w") as f:
    f.write(content)

# Verify
with open("/home/fash/uip/enricher/enricher.py", "r") as f:
    c = f.read()
print("format json:", '"format": "json"' in c)
print("think False:", '"think": False' in c)
print("JSON prompt:", "JSON object" in c)
print("json.loads in parser:", "json.loads(response)" in c)
print("fallback kept:", "text-based parsing" in c)
