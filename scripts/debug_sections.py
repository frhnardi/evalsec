import re

lines = open('tests/data/trivy_triage/005_postgres_11_postgres.yaml').readlines()

# Find sections
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.rstrip(':') in ('exploitable_findings', 'non_exploitable_findings', 'partial_findings', 'priority_order'):
        print(f'Section {stripped.rstrip(":")} at line {i}: {repr(line)}')

# Check what follows priority_order
for i in range(130, min(140, len(lines))):
    print(f'{i}: {repr(lines[i])}')
