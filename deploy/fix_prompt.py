#!/usr/bin/env python3
"""Fix the broken prompt section in enricher.py."""

with open("/home/fash/uip/enricher/enricher.py", "r") as f:
    lines = f.readlines()

# Find the broken section and replace it
new_section = [
    '        "Respond with a JSON object containing exactly these fields (keep values concise, 1-3 sentences):\\n"\n',
    '        \'{"assessed_severity": "critical|high|warning|low|info",\\n\'\n',
    '        \'"likely_cause": "root cause hypothesis",\\n\'\n',
    '        \'"remediation": "concrete triage-first steps for on-call",\\n\'\n',
    '        \'"impact_scope": "affected services/users, SLIs at risk, blast radius",\\n\'\n',
    '        \'"dedup_assessment": "DUPLICATE|CORRELATED|UNIQUE",\\n\'\n',
    '        \'"dedup_reason": "brief explanation",\\n\'\n',
    '        \'"noise_score": 1,\\n\'\n',
    '        \'"noise_reason": "why this score",\\n\'\n',
    '        \'"summary": "one-line for on-call, lead with user impact"}\\n\'\n',
    '        "Rules: assessed_severity must be one of critical/high/warning/low/info. "\n',
    '        "noise_score must be integer 1-10 (1=actionable, 10=noise). "\n',
    '        "dedup_assessment must be DUPLICATE, CORRELATED, or UNIQUE.\\n"\n',
    '    )\n',
]

# Find start line (the broken "Respond with a JSON" line)
start_idx = None
end_idx = None
for i, line in enumerate(lines):
    if '"Respond with a JSON object' in line and start_idx is None:
        start_idx = i
    if start_idx is not None and line.strip() == ')':
        end_idx = i + 1
        break

if start_idx is not None and end_idx is not None:
    lines[start_idx:end_idx] = new_section
    print(f"Replaced lines {start_idx+1}-{end_idx} with fixed prompt")
else:
    print(f"ERROR: Could not find section (start={start_idx}, end={end_idx})")

with open("/home/fash/uip/enricher/enricher.py", "w") as f:
    f.writelines(lines)

# Verify syntax
import subprocess
result = subprocess.run(
    ["python3", "-c", "import py_compile; py_compile.compile('/home/fash/uip/enricher/enricher.py', doraise=True)"],
    capture_output=True, text=True
)
if result.returncode == 0:
    print("Syntax OK")
else:
    print("Syntax ERROR:", result.stderr)
