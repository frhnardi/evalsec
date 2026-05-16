#!/usr/bin/env python3
"""Populate risk metadata fields for all findings across all trivy_triage YAML files.

Sets realistic cvss_score, epss_percentile, cisa_kev, internet_facing,
runtime_exposure, exploit_maturity, fixed_version, package_path, and
asset_criticality based on each CVE's verdict and deployment context.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

DATA_DIR = Path("tests/data/trivy_triage")

# ---------------------------------------------------------------------------
# Heuristic scoring helpers
# ---------------------------------------------------------------------------

KNOWN_KV = frozenset({
    "CVE-2021-44228",  # log4shell
    "CVE-2022-1471",   # snakeyaml RCE
    "CVE-2022-21698",  # prometheus client_golang
    "CVE-2022-40186",  # vault
    "CVE-2024-45590",  # body-parser DoS
    "CVE-2022-24434",  # dicer RCE
    "CVE-2022-29078",  # EJS RCE
    "CVE-2024-21508",  # mysql2 RCE
    "CVE-2025-15467",  # openssl
    "CVE-2026-5773",   # curl SMB
})


def _cvss_for_severity(severity: str | None, verdict: str) -> float:
    """Guess a CVSS score given Trivy severity label and our verdict."""
    if verdict == "not_exploitable":
        return 7.5  # still real CVE, just not reachable
    s = (severity or "HIGH").upper()
    if s == "CRITICAL":
        return 9.8 if verdict == "exploitable" else 7.5
    if s == "HIGH":
        return 8.2 if verdict == "exploitable" else 6.5
    if s == "MEDIUM":
        return 6.5 if verdict == "exploitable" else 5.0
    return 5.5 if verdict == "exploitable" else 4.0


def _epss_for_verdict(verdict: str) -> float:
    """Guess an EPSS percentile (0-100)."""
    if verdict == "exploitable":
        return 85.0
    if verdict == "partial":
        return 40.0
    return 10.0


def _cisa_kev(cve: str, verdict: str) -> bool | None:
    if verdict == "exploitable" and cve in KNOWN_KV:
        return True
    return None


def _exploit_maturity(verdict: str, cisa_kev: bool | None) -> str | None:
    if cisa_kev:
        return "active_exploitation"
    if verdict == "exploitable":
        return "proof_of_concept"
    return None


def _internet_facing(verdict: str, context: str) -> bool:
    """Determine if finding is internet-facing based on stack context."""
    ctx = context.lower()

    # Explicit "public internet" → definitely internet-facing
    if re.search(r"exposure\s*:\s*public\s+internet", ctx):
        return True

    # Explicit "internet-facing" → definitely internet-facing
    if "internet-facing" in ctx:
        return True

    # Explicit "exposure: internal" or "clusterip" → not internet-facing
    if re.search(r"exposure\s*:\s*internal", ctx):
        return False
    if "clusterip" in ctx:
        return False

    # Internal/VPC keywords
    internal_kw = ["vpc internal", "private subnet", "vpn access only"]
    for kw in internal_kw:
        if kw in ctx:
            return False

    # Verdict-based fallback
    if verdict == "not_exploitable":
        return False
    return True


def _runtime_exposure(verdict: str, internet_facing: bool) -> str:
    if internet_facing and verdict == "exploitable":
        return "internet_facing"
    if verdict == "exploitable":
        return "network"
    return "none"


def _asset_criticality(context: str) -> str:
    ctx = context.lower()
    if any(kw in ctx for kw in ["critical", "production", "pci", "pdp"]):
        return "high"
    if any(kw in ctx for kw in ["internal", "staging"]):
        return "medium"
    return "low"


def _extract_severity_from_input(input_text: str, cve: str) -> str | None:
    """Try to find the CVE in the scan input and extract its severity."""
    for line in input_text.split("\n"):
        if cve.lower() in line.lower():
            match = re.search(r"\|\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*\|", line, re.IGNORECASE)
            if match:
                return match.group(1).upper()
    return None


def _extract_fixed_version(input_text: str, cve: str) -> str | None:
    """Try to extract fixed version from scan input."""
    for line in input_text.split("\n"):
        if cve.lower() in line.lower():
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if "->" in part:
                    fixed = part.split("->")[-1].strip()
                    if fixed and fixed not in ("affected", ""):
                        return fixed
    return None


def _extract_package_path(input_text: str, cve: str) -> str | None:
    """Try to extract the package name from scan input."""
    for line in input_text.split("\n"):
        if cve.lower() in line.lower():
            parts = line.split("|")
            if parts:
                pkg = parts[0].strip()
                pkg = re.sub(r"^\s*[\\]?\s*", "", pkg)
                if pkg and not pkg.startswith("Total"):
                    return pkg
    return None


def populate_finding(
    finding: dict,
    verdict: str,
    input_text: str,
    context: str,
    default_severity: str | None = None,
) -> None:
    """Set risk metadata on a single finding dict."""
    cve = finding.get("cve", "")
    severity = _extract_severity_from_input(input_text, cve) or default_severity
    cvss = _cvss_for_severity(severity, verdict)
    epss = _epss_for_verdict(verdict)
    kev = _cisa_kev(cve, verdict)
    iface = _internet_facing(verdict, context)
    exposure = _runtime_exposure(verdict, iface)
    maturity = _exploit_maturity(verdict, kev)
    fixed = _extract_fixed_version(input_text, cve)
    pkg = _extract_package_path(input_text, cve)
    criticality = _asset_criticality(context)

    finding["cvss_score"] = cvss
    finding["epss_percentile"] = epss
    finding["cisa_kev"] = kev
    finding["internet_facing"] = iface
    finding["runtime_exposure"] = exposure
    finding["exploit_maturity"] = maturity
    finding["fixed_version"] = fixed
    finding["package_path"] = pkg
    finding["asset_criticality"] = criticality


def process_file(path: Path) -> bool:
    """Process a single YAML file, returning True if modified."""
    with open(path) as f:
        data = yaml.safe_load(f)

    if not data:
        return False

    ground_truth = data.get("ground_truth")
    if not ground_truth:
        return False

    input_text = data.get("input", "")
    context = data.get("stack_context", "")
    default_severity = "CRITICAL" if "CRITICAL" in input_text else "HIGH"

    modified = False

    verdict_map = {
        "exploitable_findings": "exploitable",
        "non_exploitable_findings": "not_exploitable",
        "partial_findings": "partial",
    }

    for vk, v in verdict_map.items():
        findings = ground_truth.get(vk, [])
        if not findings:
            continue
        for finding in findings:
            populate_finding(finding, v, input_text, context, default_severity)
            modified = True

    if modified:
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        return True

    return False


def main() -> None:
    files = sorted(DATA_DIR.glob("*.yaml"))
    modified = 0
    for path in files:
        if process_file(path):
            print(f"  ✅ {path.name}")
            modified += 1
        else:
            print(f"  ⏭️  {path.name} (no change)")

    print(f"\nModified {modified} of {len(files)} files.")


if __name__ == "__main__":
    main()
