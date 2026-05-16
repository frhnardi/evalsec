#!/usr/bin/env python3
"""Remove GT-only CVEs (CVEs in ground_truth but not in scan input).

Handles empty sections by writing ' []' after the section header.
Properly detects section boundaries using YAML indentation.
"""

import re
from pathlib import Path

DATA_DIR = Path("tests/data/trivy_triage")

# Files and their GT-only CVEs to remove
REMOVALS: dict[str, dict[str, list[str]]] = {
    "002_grafana_8_0_0_grafana.yaml": {
        "exploitable_findings": ["CVE-2023-3128", "CVE-2021-43798", "CVE-2022-31107"],
        "non_exploitable_findings": ["CVE-2022-27191", "CVE-2022-41715", "CVE-2022-2880", "CVE-2022-2879"],
        "priority_order": ["CVE-2023-3128", "CVE-2021-43798", "CVE-2022-31107"],
    },
    "003_mysql_5_7_mysql.yaml": {
        "exploitable_findings": ["CVE-2024-21626", "CVE-2025-31133", "CVE-2025-52565"],
        "non_exploitable_findings": ["CVE-2024-37371"],
        "priority_order": ["CVE-2024-21626", "CVE-2025-31133", "CVE-2025-52565"],
    },
    "004_nginx_1_18_nginx.yaml": {
        "exploitable_findings": ["CVE-2024-2961", "CVE-2023-4863"],
        "non_exploitable_findings": ["CVE-2019-15847"],
        "priority_order": ["CVE-2024-2961", "CVE-2023-4863"],
    },
    "005_postgres_11_postgres.yaml": {
        "exploitable_findings": ["CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881", "CVE-2024-21626"],
        "priority_order": ["CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881", "CVE-2024-21626"],
    },
    "006_python_3_8_python.yaml": {
        "exploitable_findings": ["CVE-2025-69419", "CVE-2026-28387"],
        "priority_order": ["CVE-2025-69419", "CVE-2026-28387"],
    },
    "008_redis_5_0_redis.yaml": {
        "exploitable_findings": ["CVE-2024-21626", "CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881"],
        "non_exploitable_findings": ["CVE-2024-2961", "CVE-2023-50868"],
        "priority_order": ["CVE-2024-21626", "CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881"],
    },
    "009_tomcat_9_0_30_tomcat.yaml": {
        "exploitable_findings": ["CVE-2025-24813", "CVE-2024-50379", "CVE-2025-55752"],
        "partial_findings": ["CVE-2020-8169", "CVE-2020-8177"],
        "priority_order": ["CVE-2025-24813", "CVE-2024-50379", "CVE-2025-55752", "CVE-2020-8169", "CVE-2020-8177"],
    },
    "011_elasticsearch_7_17_28_elasticsearch.yaml": {
        "exploitable_findings": ["CVE-2026-42584", "CVE-2026-42587"],
        "priority_order": ["CVE-2026-42584", "CVE-2026-42587"],
    },
    "015_prometheus_v2_30_0_prometheus.yaml": {
        "exploitable_findings": ["GHSA-4v48-4q5m-8vx4"],
        "non_exploitable_findings": ["CVE-2026-34040", "CVE-2022-30580"],
        "priority_order": ["GHSA-4v48-4q5m-8vx4"],
    },
    "018_vault_1_8_vault.yaml": {
        "exploitable_findings": ["CVE-2023-24999", "CVE-2025-6000", "CVE-2025-5999"],
        "non_exploitable_findings": ["CVE-2026-5807", "CVE-2026-3605", "CVE-2026-4525", "CVE-2026-33413"],
        "partial_findings": ["CVE-2023-24540"],
        "priority_order": ["CVE-2025-6000", "CVE-2023-24999", "CVE-2025-5999", "CVE-2023-24540"],
    },
    "022_nginx_1_18_prompt_injection.yaml": {
        "exploitable_findings": ["CVE-2024-2961"],
        "priority_order": ["CVE-2024-2961"],
    },
}


def get_top_level_keys(lines: list[str]) -> list[tuple[str, int]]:
    """Find all top-level YAML keys (indent 0) and their line numbers."""
    keys = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not stripped.startswith("-"):
            indent = len(line) - len(stripped)
            if indent == 0:
                key = stripped.split(":")[0]
                keys.append((key, i))
    return keys


def find_section_indent(lines: list[str], section_line: int) -> int:
    """Determine the indent level of a section header."""
    line = lines[section_line]
    return len(line) - len(line.lstrip())


def find_section_end(lines: list[str], section_start: int) -> int:
    """Find where a section ends by looking for the next key at same or lesser indent."""
    section_indent = find_section_indent(lines, section_start)
    i = section_start + 1
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()  # Use lstrip() to match find_section_indent
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(stripped)
        # If we hit a line that's at same or lesser indent AND is a YAML key (not a list item)
        if indent <= section_indent and not stripped.startswith("-") and ":" in stripped:
            key = stripped.split(":")[0].strip()
            # Only stop for actual YAML keys (not list items or inline values)
            if key and not key.startswith("-"):
                return i
        i += 1
    return len(lines)


def get_section_line_numbers(lines: list[str]) -> dict[str, int]:
    """Map section names to their starting line numbers."""
    sections = {}
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Match section headers like 'exploitable_findings:' or 'exploitable_findings: []'
        for name in ("exploitable_findings", "non_exploitable_findings", "partial_findings", "priority_order"):
            if stripped.startswith(name + ":") or stripped == name:
                sections[name] = i
                break
    return sections


def _section_is_inline_empty(line: str) -> bool:
    """Check if a section header line is already inline empty (e.g. 'foo: []')."""
    stripped = line.strip()
    return stripped.endswith("[]")


def remove_finding_blocks(
    lines: list[str], section_name: str, section_start: int, section_end: int, cves_to_remove: list[str]
) -> list[str]:
    """Remove finding blocks matching given CVEs from a section."""
    # If the section is already empty inline, skip it
    if _section_is_inline_empty(lines[section_start]):
        return [lines[section_start]]

    remove_set = {c.upper() for c in cves_to_remove}
    kept = []
    section_header_indent = len(lines[section_start]) - len(lines[section_start].lstrip())
    
    i = section_start + 1
    while i < section_end:
        line = lines[i]
        m = re.match(r"^\s*- cve:\s*(\S+)", line)
        if m and m.group(1).upper() in remove_set:
            # Skip this entire finding block
            i += 1
            while i < section_end:
                nline = lines[i]
                nstripped = nline.lstrip()
                nindent = len(nline) - len(nstripped)
                if nstripped.startswith("- cve:"):
                    break
                if nindent <= section_header_indent and nstripped and not nstripped.startswith("-"):
                    break
                i += 1
            continue
        kept.append(line)
        i += 1

    # If nothing was kept, emit ' []' inline
    if not kept:
        return [lines[section_start].rstrip("\n") + " []\n"]
    return [lines[section_start]] + kept


def remove_priority_order_entries(
    lines: list[str], section_start: int, section_end: int, cves_to_remove: list[str]
) -> list[str]:
    """Remove specific entries from priority_order section."""
    # If the section is already empty inline, skip it
    if _section_is_inline_empty(lines[section_start]):
        return [lines[section_start]]

    remove_set = {c.upper() for c in cves_to_remove}
    kept = []
    i = section_start + 1
    while i < section_end:
        line = lines[i]
        stripped = line.lstrip()
        m = re.match(r"^\s*-\s*(\S+)", line)
        if m and m.group(1).upper() in remove_set:
            i += 1
            continue
        kept.append(line)
        i += 1

    if not kept:
        return [lines[section_start].rstrip("\n") + " []\n"]
    return [lines[section_start]] + kept


def count_gt_cves(lines: list[str]) -> int:
    """Count all CVE entries in ground_truth (excluding NONE)."""
    count = 0
    in_gt = False
    gt_indent: int | None = None
    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith("ground_truth:"):
            in_gt = True
            gt_indent = indent
            continue
        if in_gt:
            # End of ground_truth: hit a line at same indent as ground_truth: (i.e. next top-level key)
            if indent <= (gt_indent or 0) and stripped and ":" in stripped and not stripped.startswith("-"):
                break
            m = re.match(r"^\s*- cve:\s*(\S+)", line)
            if m and m.group(1).upper() != "NONE":
                count += 1
    return count


def update_cves_selected(lines: list[str], new_count: int) -> list[str]:
    """Update the cves_selected value in source."""
    result = []
    for line in lines:
        result.append(re.sub(r"^(\s+cves_selected:\s*)\d+", rf"\g<1>{new_count}", line))
    return result


def main() -> None:
    for fname, removals in sorted(REMOVALS.items()):
        path = DATA_DIR / fname
        if not path.exists():
            print(f"SKIP: {fname} not found")
            continue

        with open(path) as f:
            lines = f.readlines()

        sections = get_section_line_numbers(lines)

        # Compute section ranges using indent-aware end detection
        section_order = ["exploitable_findings", "non_exploitable_findings", "partial_findings", "priority_order"]
        section_ranges = []
        for sn in section_order:
            if sn in sections:
                start = sections[sn]
                end = find_section_end(lines, start)
                section_ranges.append((sn, start, end))

        # Apply edits bottom-to-top to avoid index drift
        for sn, start, end in reversed(section_ranges):
            if sn not in removals:
                continue
            if sn == "priority_order":
                new_block = remove_priority_order_entries(lines, start, end, removals[sn])
            else:
                new_block = remove_finding_blocks(lines, sn, start, end, removals[sn])
            lines[start:end] = new_block

        # Update cves_selected
        gt_count = count_gt_cves(lines)
        lines = update_cves_selected(lines, gt_count)

        with open(path, "w") as f:
            f.writelines(lines)

        print(f"OK: {fname} (cves_selected={gt_count})")


if __name__ == "__main__":
    main()
