#!/usr/bin/env python3
"""Inject missing scan CVEs into YAML input field and restore removed findings.

For the 3 critical cases (005_postgres, 008_redis, 018_vault), the
fix_gt_only_cves.py script removed CVEs from ground_truth that ARE present
in the full scan files (scans/*.txt) but were truncated from the YAML
input: field (because Trivy's compact format only shows the first CVE per
library in some cases).

This script injects those missing scan lines back into the input: field
and restores the removed CVEs in ground_truth.

Usage:
    python scripts/inject_missing_scan_cves.py
"""

import re
from pathlib import Path

import yaml


DATA_DIR = Path("tests/data/trivy_triage")


# ── Injections: compact-format lines to add to the input: field ──────────

# Each entry specifies:
#   anchor_text: text in the input string to search for (the CVE line we
#                insert AFTER)
#   lines: list of compact-format scan lines to inject (each will be
#          prepended with a newline)

INJECTIONS: dict[str, dict] = {
    # ── 005_postgres: gosu (gobinary) runc CVEs truncated ────────────────
    "005_postgres_11_postgres.yaml": {
        "anchor_text": (
            "github.com/opencontainers/runc | CVE-2023-27561 | HIGH | fixed"
            " | v1.0.1 -> 1.1.5 | https://avd.aquasec.com/nvd/cve-2023-27561"
        ),
        "lines": [
            (
                "  github.com/opencontainers/runc | CVE-2024-21626 | HIGH | fixed"
                " | v1.0.1 -> 1.1.12 | https://avd.aquasec.com/nvd/cve-2024-21626"
            ),
            (
                "  github.com/opencontainers/runc | CVE-2025-31133 | HIGH | fixed"
                " | v1.0.1 -> 1.2.8, 1.3.3, 1.4.0-rc.3"
                " | https://avd.aquasec.com/nvd/cve-2025-31133"
            ),
            (
                "  github.com/opencontainers/runc | CVE-2025-52565 | HIGH | affected"
                " | v1.0.1 | https://avd.aquasec.com/nvd/cve-2025-52565"
            ),
            (
                "  github.com/opencontainers/runc | CVE-2025-52881 | HIGH | affected"
                " | v1.0.1 | https://avd.aquasec.com/nvd/cve-2025-52881"
            ),
        ],
    },
    # ── 008_redis: gosu (gobinary) runc CVEs truncated ───────────────────
    "008_redis_5_0_redis.yaml": {
        "anchor_text": (
            "github.com/opencontainers/runc | CVE-2023-27561 | HIGH | fixed"
            " | v1.0.1 -> 1.1.5 | https://avd.aquasec.com/nvd/cve-2023-27561"
        ),
        "lines": [
            (
                "  github.com/opencontainers/runc | CVE-2024-21626 | HIGH | fixed"
                " | v1.0.1 -> 1.1.12 | https://avd.aquasec.com/nvd/cve-2024-21626"
            ),
            (
                "  github.com/opencontainers/runc | CVE-2025-31133 | HIGH | fixed"
                " | v1.0.1 -> 1.2.8, 1.3.3, 1.4.0-rc.3"
                " | https://avd.aquasec.com/nvd/cve-2025-31133"
            ),
            (
                "  github.com/opencontainers/runc | CVE-2025-52565 | HIGH | affected"
                " | v1.0.1 | https://avd.aquasec.com/nvd/cve-2025-52565"
            ),
            (
                "  github.com/opencontainers/runc | CVE-2025-52881 | HIGH | affected"
                " | v1.0.1 | https://avd.aquasec.com/nvd/cve-2025-52881"
            ),
        ],
    },
    # ── 018_vault: gobinary vault CVEs truncated ─────────────────────────
    "018_vault_1_8_vault.yaml": {
        "anchor_text": "stdlib | CVE-2023-24538 | CRITICAL | v1.16.15 -> 1.19.8, 1.20.3 | https://avd.aquasec.com/nvd/cve-2023-24538",
        "lines": [
            (
                "  github.com/hashicorp/vault | CVE-2025-6000 | CRITICAL | fixed"
                " | 1.8.12 -> 1.20.1 | https://avd.aquasec.com/nvd/cve-2025-6000"
            ),
            (
                "  github.com/hashicorp/vault | CVE-2023-24999 | HIGH | fixed"
                " | 1.8.12 -> 1.10.11, 1.11.8, 1.12.4"
                " | https://avd.aquasec.com/nvd/cve-2023-24999"
            ),
            (
                "  github.com/hashicorp/vault | CVE-2025-5999 | HIGH | fixed"
                " | 1.8.12 -> 1.20.0 | https://avd.aquasec.com/nvd/cve-2025-5999"
            ),
            (
                "  stdlib | CVE-2023-24540 | HIGH | fixed"
                " | v1.16.15 -> 1.19.9, 1.20.4"
                " | https://avd.aquasec.com/nvd/cve-2023-24540"
            ),
            (
                "  go.etcd.io/etcd | CVE-2026-33413 | HIGH | affected"
                " | v0.5.0-alpha.5.0.20200425165423-262c93980547"
                " | https://avd.aquasec.com/nvd/cve-2026-33413"
            ),
            (
                "  github.com/hashicorp/vault | CVE-2026-3605 | HIGH | affected"
                " | 1.8.12 | https://avd.aquasec.com/nvd/cve-2026-3605"
            ),
            (
                "  github.com/hashicorp/vault | CVE-2026-4525 | HIGH | affected"
                " | 1.8.12 | https://avd.aquasec.com/nvd/cve-2026-4525"
            ),
            (
                "  github.com/hashicorp/vault | CVE-2026-5807 | HIGH | affected"
                " | 1.8.12 | https://avd.aquasec.com/nvd/cve-2026-5807"
            ),
        ],
    },
}


# ── Findings to restore in ground_truth ──────────────────────────────────
# Keyed by filename, same CVEs that fix_gt_only_cves.py removed.

RESTORE_FINDINGS: dict = {
    "005_postgres_11_postgres.yaml": {
        "exploitable_findings": [
            {
                "cve": "CVE-2025-31133",
                "verdict": "exploitable",
                "reasoning": (
                    "runc container escape via masked path mount race — gosu binary in image,"
                    " writable filesystem + seccomp default allows exploitation in container escape scenario."
                ),
                "action": "Rebuild image with gosu updated to runc >= 1.2.8 or 1.3.3.",
            },
            {
                "cve": "CVE-2025-52565",
                "verdict": "exploitable",
                "reasoning": (
                    "runc container escape via malicious config /dev/console mount — gosu embeds runc,"
                    " writable filesystem, potential for container breakout."
                ),
                "action": "Rebuild image with updated gosu containing runc fix when available.",
            },
            {
                "cve": "CVE-2025-52881",
                "verdict": "exploitable",
                "reasoning": (
                    "runc container escape via opencontainers/selinux arbitrary write —"
                    " gosu embeds runc, container escape risk."
                ),
                "action": "Rebuild image with updated gosu containing runc fix when available.",
            },
            {
                "cve": "CVE-2024-21626",
                "verdict": "exploitable",
                "reasoning": (
                    "runc file descriptor leak — gosu in image, writable filesystem,"
                    " container escape via leaked fd to host filesystem."
                ),
                "action": "Rebuild image with gosu updated to runc >= 1.1.12.",
            },
        ],
        "priority_order": [
            "CVE-2025-31133",
            "CVE-2025-52565",
            "CVE-2025-52881",
            "CVE-2024-21626",
        ],
    },
    "008_redis_5_0_redis.yaml": {
        "exploitable_findings": [
            {
                "cve": "CVE-2024-21626",
                "verdict": "exploitable",
                "reasoning": (
                    "runc file descriptor leak — gosu binary in image with writable cache dirs,"
                    " potential container escape via leaked fd."
                ),
                "action": "Rebuild image with gosu updated to runc >= 1.1.12.",
            },
            {
                "cve": "CVE-2025-31133",
                "verdict": "exploitable",
                "reasoning": (
                    "runc container escape via masked path mount race — gosu embeds runc,"
                    " container breakout risk with writable temp directories."
                ),
                "action": "Rebuild image with gosu updated to runc >= 1.2.8 or 1.3.3.",
            },
            {
                "cve": "CVE-2025-52565",
                "verdict": "exploitable",
                "reasoning": (
                    "runc container escape via malicious config /dev/console mount —"
                    " gosu embeds runc, container breakout potential."
                ),
                "action": "Rebuild image with updated gosu containing runc fix when available.",
            },
            {
                "cve": "CVE-2025-52881",
                "verdict": "exploitable",
                "reasoning": (
                    "runc container escape via opencontainers/selinux arbitrary write —"
                    " gosu embeds runc, container escape risk."
                ),
                "action": "Rebuild image with updated gosu containing runc fix when available.",
            },
        ],
        "priority_order": [
            "CVE-2024-21626",
            "CVE-2025-31133",
            "CVE-2025-52565",
            "CVE-2025-52881",
        ],
    },
    "018_vault_1_8_vault.yaml": {
        "exploitable_findings": [
            {
                "cve": "CVE-2025-6000",
                "verdict": "exploitable",
                "reasoning": (
                    "Vault Plugin Code Execution — Vault core vuln, critical infra dengan NetworkPolicy"
                    " allow all inbound, dampak total secrets disclosure."
                ),
                "action": "Segera upgrade Vault ke versi 1.20.1+.",
            },
            {
                "cve": "CVE-2023-24999",
                "verdict": "exploitable",
                "reasoning": (
                    "Vault fails to verify Approle SecretID belongs to role — auth bypass,"
                    " akses NetworkPolicy luas, dampak kritis untuk secrets manager."
                ),
                "action": "Segera upgrade Vault ke versi 1.10.11+, 1.11.8+, atau 1.12.4+.",
            },
            {
                "cve": "CVE-2025-5999",
                "verdict": "exploitable",
                "reasoning": (
                    "Vault Identity Token Privilege Escalation — Vault core vuln,"
                    " memungkinkan privesc, dampak kritis pada platform secrets."
                ),
                "action": "Segera upgrade Vault ke versi 1.20.0+.",
            },
        ],
        "non_exploitable_findings": [
            {
                "cve": "CVE-2026-5807",
                "verdict": "not_exploitable",
                "reasoning": (
                    "Vault DoS via unauthenticated root token generation — DoS only,"
                    " tidak menyebabkan kebocoran data, Vault di internal cluster."
                ),
                "action": "Monitor untuk patch selanjutnya.",
            },
            {
                "cve": "CVE-2026-3605",
                "verdict": "not_exploitable",
                "reasoning": (
                    "Vault DoS via unauthorized secret deletion — DoS only,"
                    " Vault diaudit, terdeteksi, dampak terbatas."
                ),
                "action": "Monitor untuk patch selanjutnya.",
            },
            {
                "cve": "CVE-2026-4525",
                "verdict": "not_exploitable",
                "reasoning": (
                    "Vault info disclosure via incorrect header handling —"
                    " membutuhkan akses network ke Vault API, internal cluster."
                ),
                "action": "Terapkan NetworkPolicy yang lebih ketat.",
            },
            {
                "cve": "CVE-2026-33413",
                "verdict": "not_exploitable",
                "reasoning": (
                    "etcd authorization bypass — etcd embedded, Vault tidak expose etcd API,"
                    " tidak dapat dieksploitasi dari luar."
                ),
                "action": "Monitor untuk patch selanjutnya.",
            },
        ],
        "partial_findings": [
            {
                "cve": "CVE-2023-24540",
                "verdict": "partial",
                "reasoning": (
                    "HTML template JS whitespace handling — Go stdlib vuln,"
                    " Vault kemungkinan tidak render user HTML, tapi ada resiko XSS jika template digunakan."
                ),
                "action": "Upgrade Go, verifikasi template usage.",
            },
        ],
        "priority_order": [
            "CVE-2025-6000",
            "CVE-2023-24999",
            "CVE-2025-5999",
            "CVE-2023-24540",
        ],
    },
}


# ── cves_selected updates ────────────────────────────────────────────────
# New cves_selected counts after restoration (total CVEs in ground_truth)
CVES_SELECTED: dict[str, int] = {
    "005_postgres_11_postgres.yaml": 12,  # 4 exploitable + 4 non_exploitable + 0 partial + 4 priority_order
    "008_redis_5_0_redis.yaml": 10,       # 4 exploitable + 2 non_exploitable + 0 partial + 4 priority_order
    "018_vault_1_8_vault.yaml": 12,       # 4 exploitable (3 restored + 1 existing) + 4 non_exploitable + 2 partial (1 restored + 1 existing) + 4 priority_order
}

# Wait, let me recount:
# 005: 4 exploitable + 4 non_exploitable = 8 CVEs total. cves_selected=8
# 008: 4 exploitable + 2 non_exploitable = 6 CVEs total. cves_selected=6
# 018: 4 exploitable (3 restored + CVE-2022-40186) + 4 non_exploitable + 2 partial (CVE-2023-24540 restored + CVE-2023-24538 existing) = 10 CVEs. cves_selected=10
# But wait, cves_selected is the total count of findings in ground_truth (all categories).
# Let me recount after the restoration:

# 005 post-restoration:
#   exploitable_findings: 4 (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881, CVE-2024-21626)
#   non_exploitable_findings: 4 (CVE-2019-12900, CVE-2019-8457, CVE-2018-1000858, CVE-2021-33560)
#   partial_findings: 0
#   Total: 8

# 008 post-restoration:
#   exploitable_findings: 4 (CVE-2024-21626, CVE-2025-31133, CVE-2025-52565, CVE-2025-52881)
#   non_exploitable_findings: 2 (CVE-2019-8457, CVE-2023-50387)
#   partial_findings: 0
#   Total: 6

# 018 post-restoration:
#   exploitable_findings: 4 (CVE-2022-40186 existing + CVE-2025-6000, CVE-2023-24999, CVE-2025-5999 restored)
#   non_exploitable_findings: 4 (CVE-2026-5807, CVE-2026-3605, CVE-2026-4525, CVE-2026-33413)
#   partial_findings: 2 (CVE-2023-24538 existing + CVE-2023-24540 restored)
#   Total: 10
# priority_order should be: CVE-2025-6000, CVE-2023-24999, CVE-2025-5999, CVE-2022-40186, CVE-2023-24540, CVE-2023-24538

CVES_SELECTED = {
    "005_postgres_11_postgres.yaml": 8,
    "008_redis_5_0_redis.yaml": 6,
    "018_vault_1_8_vault.yaml": 10,
}


def inject_into_input(input_text: str, anchor_text: str, lines: list[str]) -> str:
    """Inject compact-format scan lines into the input string after anchor_text."""
    if anchor_text not in input_text:
        # Try to find a partial match
        print(f"  WARN: anchor_text not found exactly, trying partial match...")
        # Fall back: find the last CVE line in the gosu/gobinary section
        lines_to_add = "\n".join(lines)
        # Append to the end of input
        return input_text + "\n" + lines_to_add
    idx = input_text.index(anchor_text) + len(anchor_text)
    lines_to_add = "\n" + "\n".join(lines)
    return input_text[:idx] + lines_to_add + input_text[idx:]


def _make_finding_dict(
    cve: str,
    verdict: str,
    reasoning: str,
    action: str,
) -> dict:
    """Create a finding dict with null risk metadata fields."""
    return {
        "cve": cve,
        "verdict": verdict,
        "reasoning": reasoning,
        "action": action,
        "cvss_score": None,
        "epss_percentile": None,
        "cisa_kev": None,
        "exploit_maturity": None,
        "fixed_version": None,
        "package_path": None,
        "runtime_exposure": None,
        "asset_criticality": None,
        "internet_facing": None,
    }


def process_file(fname: str) -> None:
    """Process a single YAML file."""
    path = DATA_DIR / fname
    if not path.exists():
        print(f"SKIP: {fname} not found")
        return

    with open(path) as f:
        raw_text = f.read()

    data = yaml.safe_load(raw_text)
    if data is None:
        print(f"SKIP: {fname} could not be parsed")
        return

    # ── 1. Inject missing CVEs into input field ──
    if fname in INJECTIONS:
        inj = INJECTIONS[fname]
        old_input = data.get("input", "")
        new_input = inject_into_input(old_input, inj["anchor_text"], inj["lines"])
        if new_input != old_input:
            data["input"] = new_input
            print(f"  Injected {len(inj['lines'])} scan lines into input field")
        else:
            print(f"  WARN: No changes made to input field (anchor not found?)")

    # ── 2. Restore findings in ground_truth ──
    if fname in RESTORE_FINDINGS:
        restore = RESTORE_FINDINGS[fname]
        gt = data.get("ground_truth", {})

        for category in ("exploitable_findings", "non_exploitable_findings", "partial_findings"):
            if category not in restore:
                continue
            existing_cves = {f.get("cve", "").upper(): f for f in gt.get(category, [])}
            restored_count = 0
            for fd in restore[category]:
                cve_upper = fd["cve"].upper()
                if cve_upper not in existing_cves:
                    finding = _make_finding_dict(
                        cve=fd["cve"],
                        verdict=fd["verdict"],
                        reasoning=fd["reasoning"],
                        action=fd["action"],
                    )
                    gt.setdefault(category, []).append(finding)
                    restored_count += 1
                    existing_cves[cve_upper] = finding
            if restored_count > 0:
                print(f"  Restored {restored_count} findings in {category}")

        if "priority_order" in restore:
            po_list = restore["priority_order"]
            existing_po = [p.upper() for p in gt.get("priority_order", [])]
            added = [cve for cve in po_list if cve.upper() not in existing_po]
            if added:
                gt.setdefault("priority_order", []).extend(added)
                print(f"  Added {len(added)} entries to priority_order: {added}")

        data["ground_truth"] = gt

    # ── 3. Update cves_selected (nested under source:) ──
    # Remove any top-level cves_selected (it belongs under source: per SourceInfo schema)
    if "cves_selected" in data:
        if not isinstance(data.get("cves_selected"), dict):  # not source block
            del data["cves_selected"]
    if fname in CVES_SELECTED:
        if "source" not in data:
            data["source"] = {}
        data["source"]["cves_selected"] = CVES_SELECTED[fname]
        print(f"  Updated source.cves_selected to {CVES_SELECTED[fname]}")

    # ── 4. Write back ──
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=4096)

    print(f"OK: {fname}")


def main() -> None:
    all_files = sorted(set(list(INJECTIONS.keys()) + list(RESTORE_FINDINGS.keys()) + list(CVES_SELECTED.keys())))
    for fname in all_files:
        print(f"\nProcessing: {fname}")
        process_file(fname)
    print("\nDone.")


if __name__ == "__main__":
    main()
