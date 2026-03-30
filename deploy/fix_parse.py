#!/usr/bin/env python3
"""Fix the broken parse_enrichment and dedup_assessment newline in enricher.py."""

with open("/home/fash/uip/enricher/enricher.py", "r") as f:
    content = f.read()

# Fix the split("\n") that became split("\n<actual newline>")
content = content.replace(
    'for line in response.split("\n',
    'for line in response.split("\\n'
)

# Also fix any other broken \n in the dedup_assessment line
content = content.replace(
    '"dedup_assessment must be DUPLICATE, CORRELATED, or UNIQUE.\n"',
    '"dedup_assessment must be DUPLICATE, CORRELATED, or UNIQUE.\\n"'
)

with open("/home/fash/uip/enricher/enricher.py", "w") as f:
    f.write(content)

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
