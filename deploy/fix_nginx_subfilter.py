#!/usr/bin/env python3
"""Fix broken sub_filter lines in nginx config."""

with open("/home/fash/uip/nginx/default.conf", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    stripped = line.strip()
    # Skip all broken sub_filter lines (the ones with mangled quotes)
    if stripped.startswith("sub_filter") and ("static" in stripped or "/api/" in stripped):
        continue
    # After sub_filter_types, insert correct sub_filter lines
    if "sub_filter_types" in stripped:
        new_lines.append(line)
        new_lines.append('        sub_filter \'href="/static/\' \'href="/ai/static/\';\n')
        new_lines.append('        sub_filter \'src="/static/\' \'src="/ai/static/\';\n')
        continue
    new_lines.append(line)

with open("/home/fash/uip/nginx/default.conf", "w") as f:
    f.writelines(new_lines)

print("Fixed. Last 15 lines:")
for l in new_lines[-15:]:
    print(l.rstrip())
