#!/usr/bin/env python3
"""Generate trivy_triage test cases from Trivy scan outputs using DeepSeek V4 Pro.

Pipeline:
  1. Read every .txt file in the ``scans/`` directory and map it to a
     deployment persona via filename prefix.
  2. Send the raw scan output + persona-specific deployment context to
     DeepSeek V4 Pro (via the OpenAI-compatible API).
  3. Parse the JSON response — retry with exponential backoff if invalid.
  4. Validate verdict distribution; warn if >40 % of CVEs need manual review.
  5. Build a :class:`TaskCase` Pydantic model matching the project schema.
  6. Serialise to YAML and save under ``tests/data/trivy_triage/`` with the
     naming convention ``{seq:03d}_{image_safe}_{persona_short}.yaml``.
  7. Print a formatted summary table.

Usage:
    uv run python scripts/generate_cases.py

Environment variables (loaded from ``.env``):
    DEEPSEEK_API_KEY    Required. Your DeepSeek API key.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from datetime import date, timezone
from pathlib import Path
from typing import Any

import openai
import yaml
from openai import AsyncOpenAI
from pydantic import ValidationError
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

# ---------------------------------------------------------------------------
# Ensure the project ``src`` is on ``sys.path`` so we can import evalsec
# modules from the scripts/ directory.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from evalsec.config import settings
from evalsec.tasks.base import (
    FindingDetail,
    GroundTruth,
    Rubric,
    RubricItem,
    SourceInfo,
    TaskCase,
)

# ---------------------------------------------------------------------------
# Rich console (colour output, tables)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table

    _HAS_RICH = True
    _console_instance: Console | None = Console()
    _table_class = Table
except ImportError:  # pragma: no cover
    _HAS_RICH = False
    _console_instance = None
    _table_class = None  # type: ignore[assignment]

console = _console_instance

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCANS_DIR = _PROJECT_ROOT / "scans"
OUTPUT_DIR = _PROJECT_ROOT / "tests" / "data" / "trivy_triage"
DEFAULT_ENCODING = "utf-8"

# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------
DEEPSEEK_MODEL = "deepseek-chat"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
# DeepSeek V4 Pro supports large context windows; use generous output tokens
# to avoid JSON truncation when scans contain hundreds of CVEs.
# Tested: API accepts up to 16000+ output tokens.
MAX_TOKENS = 16384
TEMPERATURE = 0.1
MAX_CONCURRENCY = 3  # Semaphore limit

# ---------------------------------------------------------------------------
# Persona definitions
# ---------------------------------------------------------------------------
PERSONA_DEFS: dict[str, dict[str, str]] = {
    "redis": {
        "persona_short": "redis",
        "display_name": "Redis 5.0 (Cache)",
        "stack_context": (
            "Service: session-cache-v1\n"
            "Image: redis:5.0 (Debian 11.5)\n"
            "Exposure: internal cluster network only (no ingress, no LoadBalancer)\n"
            "Container runtime: EKS 1.28 with:\n"
            "  - read-only root filesystem\n"
            "  - non-root user (uid 999)\n"
            "  - seccomp default profile\n"
            "  - no SYS_ADMIN capability\n"
            "  - Pod Security Standard: baseline\n"
            "  - NetworkPolicy: deny-all-ingress except from app namespace\n"
            "\n"
            "Usage: In-memory session store for a stateless PHP application.\n"
            "Only accessed via Redis protocol from application pods (port 6379 TCP).\n"
            "No authentication configured (legacy - planned upgrade to Redis 7.x ACL).\n"
            "No persistence / RDB / AOF (pure cache, data loss is acceptable).\n"
            "\n"
            "Regulatory context: Not directly customer-facing. However, session data\n"
            "may contain PII under UU PDP. Breach via Redis would require prior\n"
            "compromise of an application pod within the same namespace."
        ),
    },
    "nginx": {
        "persona_short": "nginx",
        "display_name": "nginx 1.18 (Reverse Proxy)",
        "stack_context": (
            "Service: api-gateway-v1\n"
            "Image: nginx:1.18 (Debian 10.9 - EOL)\n"
            "Exposure: public internet via ALB on ports 443 and 80 (redirect to 443)\n"
            "Container runtime: EKS 1.28 with:\n"
            "  - read-only root filesystem\n"
            "  - non-root user (uid 101)\n"
            "  - seccomp default profile\n"
            "  - no NET_RAW, no SYS_ADMIN capabilities\n"
            "  - Pod Security Standard: restricted\n"
            "  - NetworkPolicy: allow inbound from ALB only\n"
            "\n"
            "Usage: Reverse proxy terminating TLS, routing to backend services.\n"
            "Serves as the ingress point for all external traffic.\n"
            "Proxies to: payment-gateway, user-service, notification-service.\n"
            "Logs all request/response metadata for audit.\n"
            "\n"
            "Regulatory context: Supervised under OJK POJK 22/2023 (digital resilience).\n"
            "Being the public-facing entry point, any exploitable CRITICAL vulnerability\n"
            "triggers the 72-hour remediation clock (Article 18)."
        ),
    },
    "python": {
        "persona_short": "python",
        "display_name": "Python 3.8 (ML Inference)",
        "stack_context": (
            "Service: ml-inference-v2\n"
            "Image: python:3.8 (Debian 12.7)\n"
            "Exposure: internal cluster network only via ClusterIP\n"
            "Container runtime: EKS 1.28 with:\n"
            "  - read-only root filesystem\n"
            "  - non-root user (uid 1000)\n"
            "  - seccomp default profile\n"
            "  - no capabilities (drop all)\n"
            "  - Pod Security Standard: restricted\n"
            "  - NetworkPolicy: allow inbound from api-gateway namespace only\n"
            "\n"
            "Usage: Machine learning inference service (PyTorch + FastAPI).\n"
            "Processes inference requests via REST API.\n"
            "Has outbound internet access for model download from S3.\n"
            "No direct database access; uses internal REST calls to data-service.\n"
            "Long-running pods (not batch jobs).\n"
            "\n"
            "Regulatory context: Processes inference results that may contain\n"
            "indirect PII. Subject to UU PDP data protection requirements."
        ),
    },
    "postgres": {
        "persona_short": "postgres",
        "display_name": "PostgreSQL 11 (User DB)",
        "stack_context": (
            "Service: user-db-primary\n"
            "Image: postgres:11 (Debian 9.13 - EOL)\n"
            "Exposure: internal cluster network only via ClusterIP (port 5432)\n"
            "Container runtime: EKS 1.28 with:\n"
            "  - writable filesystem (required for PostgreSQL data)\n"
            "  - non-root user (uid 999)\n"
            "  - seccomp default profile\n"
            "  - no SYS_ADMIN, no NET_RAW capabilities\n"
            "  - Pod Security Standard: baseline\n"
            "  - NetworkPolicy: allow inbound from user-service namespace only\n"
            "  - Volume: 100 GB gp3 EBS volume (encrypted at rest with KMS)\n"
            "  - StatefulSet with automated backup cronjob\n"
            "\n"
            "Usage: Primary database for user-service (account management).\n"
            "Stores: user profiles, hashed passwords, MFA secrets, session tokens.\n"
            "Built-in PostgreSQL SSL/TLS configured for in-cluster traffic.\n"
            "\n"
            "Regulatory context: Contains PII under UU PDP. Database compromise\n"
            "would constitute a data breach with mandatory notification.\n"
            "OJK POJK 22/2023 Article 18 applies for critical infrastructure."
        ),
    },
    "tomcat": {
        "persona_short": "tomcat",
        "display_name": "Tomcat 9.0.30 (Legacy Portal)",
        "stack_context": (
            "Service: legacy-portal-v2\n"
            "Image: tomcat:9.0.30 (Debian 10.2 - EOL)\n"
            "Exposure: public internet via ALB on port 443\n"
            "Container runtime: EKS 1.28 with:\n"
            "  - read-only root filesystem\n"
            "  - non-root user (uid 10001)\n"
            "  - seccomp default profile\n"
            "  - no SYS_ADMIN capability\n"
            "  - Pod Security Standard: restricted\n"
            "  - NetworkPolicy: allow inbound from ALB only\n"
            "\n"
            "Usage: Java 11 (Spring Boot 2.3) web application serving the customer portal.\n"
            "Handles: login, account overview, transaction history, profile updates.\n"
            "Exposes REST and SOAP endpoints. Uses log4j 2.x for logging.\n"
            "Direct database access to user-db (PostgreSQL 11).\n"
            "\n"
            "Code reachability (verified via static analysis):\n"
            "  - log4j-core: USED extensively throughout logging framework.\n"
            "    Reachable from public HTTP handlers (all user-facing endpoints log request data).\n"
            "  - catalina.jar / coyote.jar: Core Tomcat libraries. Reachable by definition.\n"
            "  - Additional libraries may contain vulnerabilities.\n"
            "\n"
            "Regulatory context: OJK POJK 22/2023 applies. As an internet-facing service,\n"
            "CRITICAL exploitable vulnerabilities require 72-hour remediation.\n"
            "Customer PII handled, UU PDP applies."
        ),
    },
    "mysql": {
        "persona_short": "mysql",
        "display_name": "MySQL 5.7 (Transaction DB)",
        "stack_context": (
            "Service: transaction-db-v1\n"
            "Image: mysql:5.7 (Oracle Linux 7.9 - EOL)\n"
            "Exposure: internal cluster network only via ClusterIP (port 3306)\n"
            "Container runtime: EKS 1.28 with:\n"
            "  - writable filesystem (required for MySQL data)\n"
            "  - non-root user (uid 27)\n"
            "  - seccomp default profile\n"
            "  - no SYS_ADMIN, no NET_RAW capabilities\n"
            "  - Pod Security Standard: baseline\n"
            "  - NetworkPolicy: allow inbound from payment-gateway namespace only\n"
            "  - Volume: 500 GB gp3 EBS volume (encrypted at rest with KMS)\n"
            "\n"
            "Usage: Transaction database for payment-gateway service.\n"
            "Stores: transaction records, merchant settlement data, audit logs.\n"
            "No direct public access. Accessed only by payment-gateway service pods.\n"
            "Automated backups via mysqldump cronjob to S3.\n"
            "\n"
            "Regulatory context: Financial transaction data under OJK POJK 22/2023.\n"
            "PCI-DSS compliance required (cardholder data environment adjacent).\n"
            "Data retention policies apply per Indonesian banking regulations."
        ),
    },
    "rabbitmq": {
        "persona_short": "rabbitmq",
        "display_name": "RabbitMQ 3.8 (Event Bus)",
        "stack_context": (
            "Service: event-bus-v2\n"
            "Image: rabbitmq:3.8 (Ubuntu 20.04 - EOL)\n"
            "Exposure: internal cluster network only via ClusterIP (ports 5672, 15672)\n"
            "Container runtime: EKS 1.28 with:\n"
            "  - read-only root filesystem (with /var/lib/rabbitmq writable tmpfs)\n"
            "  - non-root user (uid 999)\n"
            "  - seccomp default profile\n"
            "  - no SYS_ADMIN capability\n"
            "  - Pod Security Standard: baseline\n"
            "  - NetworkPolicy: allow inbound from all namespaces in cluster (messaging infrastructure)\n"
            "\n"
            "Usage: Internal message broker for asynchronous communication between microservices.\n"
            "Manages: task queues, pub/sub topics, RPC request/reply patterns.\n"
            "Management UI (port 15672) is ClusterIP only, not externally accessible.\n"
            "TLS enabled for inter-node and client connections.\n"
            "Authentication: default credentials rotated (non-default vhost/user).\n"
            "\n"
            "Regulatory context: Underlying infrastructure for financial services (OJK).\n"
            "Message queues carry transaction events and audit data across services.\n"
            "No direct handling of PII or cardholder data (payloads opaque to RabbitMQ)."
        ),
    },
    "grafana": {
        "persona_short": "grafana",
        "display_name": "Grafana 8.0.0 (Observability)",
        "stack_context": (
            "Service: observability-dashboard\n"
            "Image: grafana/grafana:8.0.0 (Alpine 3.13.5 - EOL)\n"
            "Exposure: internal network via ALB internal scheme (port 443)\n"
            "Container runtime: EKS 1.28 with:\n"
            "  - writable /var/lib/grafana for plugin data\n"
            "  - non-root user (uid 472)\n"
            "  - seccomp default profile\n"
            "  - no SYS_ADMIN capability\n"
            "  - Pod Security Standard: baseline\n"
            "  - NetworkPolicy: allow inbound from corporate VPN CIDR only\n"
            "  - SSO via Azure AD (OAuth2)\n"
            "\n"
            "Usage: Centralized observability dashboard for DevOps and SRE teams.\n"
            "Data sources: Prometheus, CloudWatch, Elasticsearch.\n"
            "Access restricted to authorized team members via corporate VPN + SSO.\n"
            "Stores: dashboard definitions, alert configurations, data source credentials.\n"
            "Plugin support enabled for custom visualizations.\n"
            "\n"
            "Regulatory context: Does not directly process PII or transaction data.\n"
            "However, dashboards may display operational metrics that reveal\n"
            "system architecture and security posture. Access is logged and audited."
        ),
    },
}

# Maps scan filename prefix (e.g. ``redis`` from ``redis_5_0.txt``) to persona key.
PERSONA_PREFIX_MAP: dict[str, str] = {
    "redis": "redis",
    "nginx": "nginx",
    "python": "python",
    "postgres": "postgres",
    "tomcat": "tomcat",
    "mysql": "mysql",
    "rabbitmq": "rabbitmq",
    "grafana": "grafana",
}

# Maps scan filename stem to the Docker image tag for `source.image`.
# Most follow the pattern ``image:tag`` where ``_`` separates components,
# but Grafana is special (``grafana/grafana:8.0.0``).
FILENAME_TO_IMAGE: dict[str, str] = {
    "redis_5_0": "redis:5.0",
    "nginx_1_18": "nginx:1.18",
    "python_3_8": "python:3.8",
    "postgres_11": "postgres:11",
    "tomcat_9_0_30": "tomcat:9.0.30",
    "mysql_5_7": "mysql:5.7",
    "rabbitmq_3_8": "rabbitmq:3.8",
    "grafana_8_0_0": "grafana/grafana:8.0.0",
}

# ---------------------------------------------------------------------------
# System prompt for DeepSeek — instructs the model to reason about
# exploitability in the given deployment context.
#
# CRITICAL: DeepSeek output is limited to 8192 tokens (~30K chars).
# For scans with 100+ CVEs, the model MUST be extremely concise.
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """Anda adalah pakar AppSec. Tugas: analisis hasil scan Trivy untuk menentukan exploitability setiap CVE dalam konteks deployment tertentu.

Pertimbangan: internet-facing?, code reachability?, security controls (NetworkPolicy, seccomp, RO fs, non-root)?, OS EOL?, CISA KEV?, OJK POJK 22/2023, UU PDP.

**Output JSON (HARUS valid, JANGAN truncated):**
{
  "exploitable_findings": [
    {"cve":"CVE-YYYY-NNNNN","verdict":"exploitable","cvss_score":9.8,"attack_vector":"Network","reasoning":"~15 kata","action":"~15 kata"}
  ],
  "non_exploitable_findings": [
    {"cve":"CVE-YYYY-NNNNN","verdict":"not_exploitable","cvss_score":5.0,"attack_vector":"Local","reasoning":"~15 kata","action":"~10 kata"}
  ],
  "partial_findings": [
    {"cve":"CVE-YYYY-NNNNN","verdict":"partial","cvss_score":7.5,"attack_vector":"Adjacent","reasoning":"~15 kata","action":"~15 kata"}
  ],
  "priority_order": ["CVE-..."],
  "needs_review": [
    {"cve":"CVE-...","reasoning":"~15 kata"}
  ],
  "expected_response_includes": ["(?i)pattern1","(?i)pattern2","(?i)pattern3"],
  "deployment_summary": "~20 kata",
  "total_cves_analyzed": 42
}

**KRITIS — Batasan 8000 token output:**
Output JSON Anda TIDAK boleh melebihi 8000 token (~30.000 karakter). Jika melebihi, JSON akan dipotong dan dianggap gagal.

Untuk scan dengan 50+ CVE, lakukan:
1. Sangat singkat: reasoning MAX 15 kata, action MAX 15 kata. TIDAK boleh lebih.
2. Grouping: untuk CVE OS base image yang massal (Debian, Alpine, Oracle Linux) dan jelas not_exploitable, buat SATU entry representative dengan format: {"cve":"CVE-PERTAMA","verdict":"not_exploitable","reasoning":"dan {N} CVE {paket} Debian OS lainnya. Alasan: ...","action":"..."}
3. Prioritaskan CVE aplikasi (log4j, openssl, libcurl, dll) untuk entry individual.
4. Jika masih tidak muat, masukkan CVE paling tidak menarik ke `needs_review`.
5. Hanya output JSON — tanpa markdown, tanpa ```json, tanpa teks lain.

Aturan:
- `expected_response_includes`: 3-4 regex dengan (?i)
- `priority_order`: hanya dari exploitable + partial
- `attack_vector`: isi dengan Network/Local/Adjacent/None sesuai CVE
- Bahasa Indonesia untuk reasoning, action, summary"""


def _build_user_prompt(scan_text: str, stack_context: str) -> str:
    """Construct the user-turn prompt with the scan output and deployment context."""
    return (
        f"**Konteks Deployment:**\n{stack_context}\n\n"
        f"**Hasil Scan Trivy:**\n```\n{scan_text}\n```\n\n"
        "Analisis setiap CVE dan berikan output JSON sesuai instruksi sebelumnya."
    )


# ---------------------------------------------------------------------------
# Retry strategy
# ---------------------------------------------------------------------------


def _is_retryable(exc: BaseException) -> bool:
    """Return True for API errors and invalid JSON that warrant a retry."""
    if isinstance(exc, openai.APITimeoutError):
        return True
    if isinstance(exc, openai.RateLimitError):
        return True
    if isinstance(exc, openai.APIStatusError):
        return exc.status_code >= 500
    if isinstance(exc, json.JSONDecodeError):
        return True
    return False


_CALL_RETRY = retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=8),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)


# ---------------------------------------------------------------------------
# Scan-file helpers
# ---------------------------------------------------------------------------


def _discover_scan_files() -> list[Path]:
    """Return sorted list of ``.txt`` files in the scans directory."""
    files = sorted(SCANS_DIR.glob("*.txt"))
    if not files:
        msg = f"No ``.txt`` files found in {SCANS_DIR}"
        raise FileNotFoundError(msg)
    return files


def _resolve_persona(stem: str) -> tuple[str, str] | None:
    """Map a scan filename stem to ``(persona_key, persona_short)`` or ``None``.

    Example:
        ``redis_5_0`` → ``("redis", "redis")``
    """
    for prefix, key in PERSONA_PREFIX_MAP.items():
        if stem.startswith(prefix):
            return key, PERSONA_DEFS[key]["persona_short"]
    return None


def _compute_next_seq(output_dir: Path) -> int:
    """Determine the next sequence number for a new YAML file.

    Scans existing ``*.yaml`` files in *output_dir* and returns
    ``max(seq) + 1`` (starting from 2 if the directory is empty except for
    the canonical ``001_log4shell_reachable.yaml``).
    """
    max_seq = 0
    for yaml_file in sorted(output_dir.glob("*.yaml")):
        # Parse the 3-digit sequence from the filename
        m = re.match(r"^(\d{3})_", yaml_file.stem)
        if m:
            seq = int(m.group(1))
            if seq > max_seq:
                max_seq = seq
    return max(2, max_seq + 1)  # start at 002 minimum


def _parse_total_cves(scan_text: str) -> int:
    """Parse the total number of CVEs from Trivy scan output.

    Sums all ``Total: N`` lines in the report (one per target/scanner).
    """
    total = 0
    for line in scan_text.splitlines():
        m = re.match(r"^Total:\s*(\d+)", line)
        if m:
            total += int(m.group(1))
    return total


# ---------------------------------------------------------------------------
# CVE selection filter — keep YAML files small (max ~10 CVEs per case)
# ---------------------------------------------------------------------------

SELECTION_CRITERIA = "top 4 exploitable + 2 partial + 4 not_exploitable (interesting)"


def _select_cves(parsed: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Filter DeepSeek response to a compact set of CVEs for the YAML output.

    Selection priority:
    1. All exploitable CVEs (max 4)
    2. All partial CVEs (max 2)
    3. Most *interesting* not_exploitable CVEs — prefer those with
       ``attack_vector="Network"``, then by descending ``cvss_score`` (max 4).

    Returns *(filtered_parsed, selection_stats)* where *selection_stats* contains
    the CVE IDs that were kept and the counts for the ``SourceInfo`` fields.
    """
    exploitable = list(parsed.get("exploitable_findings", []))
    partial = list(parsed.get("partial_findings", []))
    not_exploitable = list(parsed.get("non_exploitable_findings", []))
    needs_review = list(parsed.get("needs_review", []))

    all_cves: set[str] = set()
    for item in exploitable + partial + not_exploitable + needs_review:
        cve = str(item.get("cve", ""))
        if cve:
            all_cves.add(cve)

    total_before = len(all_cves)

    # Step 1: exploitable — keep ALL (max 4)
    selected_exploitable = exploitable[:4]

    # Step 2: partial — keep ALL (max 2)
    selected_partial = partial[:2]

    # Step 3: not_exploitable — pick most interesting (max 4)
    # Sort: Network attack_vector first, then by cvss_score descending
    def _interest_key(item: dict[str, Any]) -> tuple:
        av = str(item.get("attack_vector", "") or "")
        is_network = 0 if av.lower() == "network" else 1
        cvss = float(item.get("cvss_score", 0) or 0)
        return (is_network, -cvss)

    sorted_ne = sorted(not_exploitable, key=_interest_key)
    selected_ne = sorted_ne[:4]

    # Build the set of selected CVE IDs
    selected_ids: set[str] = set()
    for item in selected_exploitable:
        cve = str(item.get("cve", ""))
        if cve:
            selected_ids.add(cve)
    for item in selected_partial:
        cve = str(item.get("cve", ""))
        if cve:
            selected_ids.add(cve)
    for item in selected_ne:
        cve = str(item.get("cve", ""))
        if cve:
            selected_ids.add(cve)

    # Filter priority_order to only include selected CVEs
    priority = parsed.get("priority_order", [])
    filtered_priority = [cve for cve in priority if cve in selected_ids]

    # Build the filtered response
    filtered: dict[str, Any] = {
        "exploitable_findings": selected_exploitable,
        "partial_findings": selected_partial,
        "non_exploitable_findings": selected_ne,
        "needs_review": needs_review,
        "priority_order": filtered_priority,
        "expected_response_includes": parsed.get("expected_response_includes", []),
        "deployment_summary": parsed.get("deployment_summary", ""),
        "total_cves_analyzed": len(selected_ids),
    }

    stats: dict[str, Any] = {
        "total_cves_found": total_before,
        "cves_selected": len(selected_ids),
        "selection_criteria": SELECTION_CRITERIA,
        "selected_cve_ids": sorted(selected_ids),
    }

    return filtered, stats


# ---------------------------------------------------------------------------
# Scan-text filter — keep only Trivy output lines for selected CVEs
# ---------------------------------------------------------------------------

_CVE_PATTERN = re.compile(r"CVE-\d+-\d+")


def _condense_cve_line(group_lines: list[str]) -> str:
    """Extract key CVE fields from a Trivy row group and return one compact line.

    The approach uses the *first* row of the group (which contains all primary
    columns) and supplements with regex searches across the full group text.
    """
    first = group_lines[0] if group_lines else ""
    full = " ".join(ln.strip() for ln in group_lines if ln.strip())

    # -- CVE ID (regex) --
    cve_match = _CVE_PATTERN.search(full)
    cve = cve_match.group(0) if cve_match else "???"

    # -- Library name (first column of first row, strip box-drawing chars) --
    lib = first.strip().lstrip("\u2502\u2503│┃").strip()
    # Take everything before the first column separator
    lib = lib.split("\u2502")[0].split("│")[0].split("┃")[0].strip()

    # -- Severity (regex across full group text) --
    severity = ""
    sev_match = re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", full)
    if sev_match:
        severity = sev_match.group(1)

    # -- Status (affected|fixed) --
    status = ""
    for token in ("affected", "fixed"):
        if re.search(rf"\b{token}\b", full, re.IGNORECASE):
            status = token
            break

    # -- Installed / fixed versions --
    # Trivy table rows start with │, so split produces: ['' | lib | CVE | sev | status | installed | fixed | title | '']
    # Indices:                                 [0]  [1]   [2]   [3]   [4]      [5]        [6]     [7]     [8]
    installed = ""
    fixed = ""
    cols = first.split("\u2502")
    if len(cols) < 5:
        cols = first.split("│")
    if len(cols) >= 7:
        installed = cols[5].strip()
        fixed = cols[6].strip()
    elif len(cols) >= 6:
        installed = cols[5].strip()

    # Clean up — remove empty/box-drawing-only results
    installed = re.sub(r"[^\w.~+\-:,;/ ]", "", installed).strip()
    fixed = re.sub(r"[^\w.~+\-:,;/ ]", "", fixed).strip()

    # -- URL --
    url = ""
    url_match = re.search(r"https?://\S+", full)
    if url_match:
        url = url_match.group(0)

    # Assemble compact line
    parts_out = [cve]
    if severity:
        parts_out.append(severity)
    if status:
        parts_out.append(status)
    if lib:
        parts_out.insert(0, lib)
    # Version info
    ver = ""
    if installed and fixed and installed != fixed:
        ver = f"{installed} -> {fixed}"
    elif fixed:
        ver = f"-> {fixed}"
    elif installed:
        ver = installed
    if ver:
        parts_out.append(ver)
    if url:
        parts_out.append(url)

    return " | ".join(parts_out)


def _filter_scan_text(scan_text: str, selected_cves: set[str]) -> str:
    """Filter Trivy scan output to only include lines for selected CVEs.

    Non-table lines (timestamps, section headers, the Report-Summary table)
    are kept as-is.  Vulnerability tables are parsed and condensed — each
    selected CVE produces one compact line:

        Library | CVE-ID | SEVERITY | status | installed -> fixed | URL

    Tables with no matching CVEs are dropped entirely.
    """
    lines = scan_text.splitlines()
    result: list[str] = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Detect start of any Trivy table
        if line.startswith("\u250c"):  # ┌
            table_lines: list[str] = []
            while i < len(lines) and not lines[i].startswith("\u2514"):  # └
                table_lines.append(lines[i])
                i += 1
            if i < len(lines):
                table_lines.append(lines[i])  # closing └
            i += 1  # skip └ so outer loop doesn't re-add it

            full_table = " ".join(table_lines)
            is_summary = "Target" in full_table and "Vulnerabilities" in full_table

            if is_summary:
                # Keep the Report-Summary table as-is
                result.extend(table_lines)
                continue

            # -- Vulnerability table -- parse rows and condense ----------------
            # Find header separator (first ├ or ┼ line)
            header_end = 1
            for idx, tl in enumerate(table_lines):
                if "\u253c" in tl[:3] or (tl.startswith("\u251c") and idx > 0):
                    header_end = idx
                    break

            # Parse row groups from data area
            data_start = header_end + 1
            row_groups: list[list[str]] = []
            current_group: list[str] = []

            for dl in table_lines[data_start:-1]:
                if dl.startswith("\u251c") or dl.startswith("\u253c"):
                    if current_group:
                        row_groups.append(current_group)
                        current_group = []
                else:
                    current_group.append(dl)
            if current_group:
                row_groups.append(current_group)

            # Filter row groups -- keep only those with a selected CVE
            for group in row_groups:
                group_text = " ".join(group)
                group_cves = set(_CVE_PATTERN.findall(group_text))
                if group_cves & selected_cves:
                    condensed = _condense_cve_line(group)
                    result.append(f"  {condensed}")

        else:
            result.append(line)
            i += 1

    return "\n".join(result)


# ---------------------------------------------------------------------------
# DeepSeek API call
# ---------------------------------------------------------------------------


@_CALL_RETRY
async def _call_deepseek(
    client: AsyncOpenAI,
    system_prompt: str,
    user_prompt: str,
) -> dict[str, Any]:
    """Send a chat completion request to DeepSeek and return the parsed JSON.

    Raises:
        json.JSONDecodeError: If the model output is not valid JSON (retried).
        openai.APIError: For non-retryable API errors.
    """
    response = await client.chat.completions.create(
        model=DEEPSEEK_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=MAX_TOKENS,
        temperature=TEMPERATURE,
    )

    finish_reason = response.choices[0].finish_reason
    raw_text = response.choices[0].message.content or ""

    # Detect truncation — if the response was cut off, the JSON is guaranteed
    # to be invalid. Raise json.JSONDecodeError to trigger a tenacity retry.
    if finish_reason == "length":
        raise json.JSONDecodeError(
            f"Response truncated at {len(raw_text)} chars "
            f"(finish_reason=length, max_tokens={MAX_TOKENS}). "
            f"Retrying with backoff...",
            raw_text,
            0,
        )

    # Strip markdown code fences if present
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        # Remove opening fence (possibly with language hint)
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        # Remove closing fence
        cleaned = re.sub(r"\n?```\s*$", "", cleaned)
        cleaned = cleaned.strip()

    if not cleaned:
        raise json.JSONDecodeError("Empty response from model", cleaned, 0)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Log the raw response for debugging before re-raising
        debug_path = _PROJECT_ROOT / "scripts" / "_debug_response.txt"
        debug_path.write_text(
            f"finish_reason: {finish_reason}\n"
            f"raw_length: {len(raw_text)}\n"
            f"cleaned_length: {len(cleaned)}\n"
            f"--- RAW RESPONSE ---\n{raw_text}\n"
        )
        raise


# ---------------------------------------------------------------------------
# Data transformation
# ---------------------------------------------------------------------------


def _build_finding_detail(
    item: dict[str, Any],
    default_verdict: str = "not_exploitable",
) -> FindingDetail:
    """Build a :class:`FindingDetail` from a DeepSeek JSON item.

    Args:
        item: A dict with keys ``cve``, ``verdict``, ``reasoning``, ``action``.
        default_verdict: Fallback if *item* lacks a ``verdict`` key.
    """
    verdict_raw = item.get("verdict", default_verdict)
    # Normalise: deepseek may return "not_exploitable" or "not exploitable"
    verdict = verdict_raw.replace(" ", "_").replace("-", "_").lower()
    # Map to allowed values
    verdict_map = {
        "exploitable": "exploitable",
        "not_exploitable": "not_exploitable",
        "not exploitable": "not_exploitable",
        "partial": "partial",
    }
    verdict = verdict_map.get(verdict, default_verdict)

    return FindingDetail(
        cve=str(item.get("cve", "")),
        verdict=verdict,
        reasoning=str(item.get("reasoning", "")),
        action=str(item.get("action")) if item.get("action") else None,
    )


def _build_task_case(
    seq: int,
    stem: str,
    filtered_scan_text: str,
    persona_key: str,
    parsed: dict[str, Any],
    notes_parts: list[str],
    source_extras: dict[str, Any] | None = None,
) -> TaskCase:
    """Assemble a :class:`TaskCase` from the DeepSeek response.

    Args:
        seq: Sequence number for the test case ID.
        stem: Scan filename stem (e.g. ``redis_5_0``).
        filtered_scan_text: Trivy output filtered to only include selected CVEs.
        persona_key: Key into :data:`PERSONA_DEFS`.
        parsed: The (already filtered) DeepSeek JSON response.
        notes_parts: Accumulator for notes strings.
        source_extras: Optional extra fields for ``SourceInfo`` (e.g.
            ``total_cves_found``, ``cves_selected``, ``selection_criteria``).
    """
    persona = PERSONA_DEFS[persona_key]
    image_name = FILENAME_TO_IMAGE.get(stem, stem.replace("_", ":"))
    image_safe = stem  # e.g. ``redis_5_0`` — safe for filenames

    # Convert needs_review items into a notes string
    needs_review_list = parsed.get("needs_review", [])
    needs_review_cves = [nr.get("cve", "?") for nr in needs_review_list]
    if needs_review_cves:
        notes_parts.append(
            f"CVEs requiring manual review ({len(needs_review_cves)}): "
            f"{', '.join(needs_review_cves)}"
        )

    # Build the ground truth — skip needs_review items
    exploitable = [
        _build_finding_detail(item, "exploitable")
        for item in parsed.get("exploitable_findings", [])
    ]
    non_exploitable = [
        _build_finding_detail(item, "not_exploitable")
        for item in parsed.get("non_exploitable_findings", [])
    ]
    partial = [
        _build_finding_detail(item, "partial") for item in parsed.get("partial_findings", [])
    ]

    ground_truth = GroundTruth(
        exploitable_findings=exploitable,
        non_exploitable_findings=non_exploitable,
        partial_findings=partial,
        priority_order=parsed.get("priority_order", []),
    )

    # expected_response_includes — use what DeepSeek returned, or sensible defaults
    expected_includes: list[str] = parsed.get("expected_response_includes", [])
    if not expected_includes:
        expected_includes = [
            "(?i)exploitable|reachable",
            "(?i)not reachable|false positive|dead code",
            "(?i)patch|remediat|rekomendasi|fix",
        ]

    # Default rubric (25 points per dimension)
    rubric = Rubric(
        reachability_reasoning=RubricItem(
            max_score=25,
            description=(
                "Does the model use the stack context to determine real exploitability? "
                "Full marks: correctly identifies which CVEs are reachable vs unreachable. "
                "Zero marks: ignores deployment context, treats all CRITICAL as exploitable."
            ),
        ),
        prioritization=RubricItem(
            max_score=25,
            description=(
                "Does the model rank findings correctly by real-world urgency? "
                "Exploitable internet-facing CVEs must be prioritised over non-exploitable ones. "
                "Penalize if the model treats all CRITICAL as equally urgent."
            ),
        ),
        actionability=RubricItem(
            max_score=25,
            description=(
                "Are recommended actions concrete and specific? "
                "Good: 'Patch library X to version Y, deploy within 72 hours per OJK 22/2023.' "
                "Bad: 'Update vulnerable dependencies.'"
            ),
        ),
        conciseness=RubricItem(
            max_score=25,
            description=(
                "Response is under 12 sentences. No preamble. "
                "No excessive caveats. Direct, professional tone."
            ),
        ),
    )

    # notes string
    notes = "\n".join(notes_parts) if notes_parts else None

    # Build SourceInfo with optional selection extras
    source_kwargs: dict[str, Any] = dict(
        type="ai_assisted_deepseek_v4",
        image=image_name,
        scanned_at=date.today(),
        trivy_version="auto_detected",
        notes=notes,
    )
    if source_extras:
        source_kwargs.update(source_extras)

    return TaskCase(
        id=f"trivy_triage_{seq:03d}",
        task="trivy_triage",
        version="v1",
        source=SourceInfo(**source_kwargs),
        input=filtered_scan_text,
        stack_context=persona["stack_context"],
        ground_truth=ground_truth,
        expected_response_includes=expected_includes,
        rubric=rubric,
        weight=1.0,
    )


# ---------------------------------------------------------------------------
# YAML serialisation
# ---------------------------------------------------------------------------


class _CustomYamlDumper(yaml.SafeDumper):
    """YAML dumper that handles ``date`` objects by emitting YAML timestamps."""


def _represent_date(dumper: yaml.SafeDumper, data: date) -> yaml.Node:
    """Emit a ``date`` as an unquoted YAML timestamp (``2026-05-14``).

    PyYAML will parse this back as a ``datetime.date``, which satisfies
    Pydantic strict mode for ``date`` fields.
    """
    return dumper.represent_scalar(
        "tag:yaml.org,2002:timestamp",
        data.isoformat(),
        style="",  # unquoted
    )


_CustomYamlDumper.add_representer(date, _represent_date)


def _serialise_task_case(task_case: TaskCase) -> str:
    """Convert a :class:`TaskCase` to a YAML string.

    Uses ``model_dump(mode="python")`` for rich types (date),
    with a custom representer to serialise ``date`` as ISO string.
    """
    data = task_case.model_dump(mode="python")
    return yaml.dump(
        data,
        Dumper=_CustomYamlDumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=100,
    )


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_needs_review_ratio(parsed: dict[str, Any], persona_name: str) -> str | None:
    """Warn if >40 % of CVEs are marked ``needs_review``.

    Returns a warning string or ``None``.
    """
    total = parsed.get("total_cves_analyzed", 0)
    needs_review = len(parsed.get("needs_review", []))
    if total > 0 and needs_review / total > 0.4:
        pct = (needs_review / total) * 100
        return (
            f"[yellow]WARNING[/yellow] {persona_name}: {needs_review}/{total} "
            f"({pct:.0f}%) CVEs marked 'needs_review' — verifying results is advised."
        )
    return None


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------


def _print_header(text: str) -> None:
    """Print a section header."""
    if console:
        console.rule(f"[bold]{text}[/bold]", style="dim blue")
    else:
        print(f"\n=== {text} ===")


def _print_info(text: str) -> None:
    """Print an info line."""
    if console:
        console.print(text)
    else:
        print(text)


def _print_error(text: str) -> None:
    """Print an error line."""
    if console:
        console.print(f"[red]{text}[/red]")
    else:
        print(f"ERROR: {text}")


def _print_success(text: str) -> None:
    """Print a success line."""
    if console:
        console.print(f"[green]{text}[/green]")
    else:
        print(text)


# ---------------------------------------------------------------------------
# Per-scan-file worker
# ---------------------------------------------------------------------------


async def _process_scan(
    sem: asyncio.Semaphore,
    client: AsyncOpenAI,
    scan_path: Path,
    seq: int,
    warnings: list[str],
) -> dict[str, Any] | None:
    """Process a single scan file: call DeepSeek, build YAML, validate, save.

    Returns a summary dict on success, or ``None`` on failure.
    """
    stem = scan_path.stem  # filename without .txt
    async with sem:
        # ── 1. Resolve persona ──────────────────────────────────────────
        persona_match = _resolve_persona(stem)
        if persona_match is None:
            _print_error(f"{stem}: No matching persona found. Skipping.")
            return None

        persona_key, persona_short = persona_match
        persona = PERSONA_DEFS[persona_key]
        display_name = persona["display_name"]
        stack_context = persona["stack_context"]
        image_name = FILENAME_TO_IMAGE.get(stem, stem.replace("_", ":"))

        _print_info(f"  {display_name} ({image_name}) — calling DeepSeek ...")

        # ── 2. Read scan file ───────────────────────────────────────────
        scan_text = scan_path.read_text(encoding=DEFAULT_ENCODING, errors="replace")

        # ── 3. Call DeepSeek ────────────────────────────────────────────
        user_prompt = _build_user_prompt(scan_text, stack_context)

        try:
            parsed = await _call_deepseek(client, SYSTEM_PROMPT, user_prompt)
        except json.JSONDecodeError as exc:
            _print_error(f"{stem}: Invalid JSON after 3 retries: {exc}")
            return None
        except openai.APIError as exc:
            _print_error(f"{stem}: DeepSeek API error after 3 retries: {exc}")
            return None
        except Exception as exc:
            _print_error(f"{stem}: Unexpected error: {exc}")
            return None

        # ── 4. Validate needs_review ratio ──────────────────────────────
        warning = _check_needs_review_ratio(parsed, display_name)
        if warning:
            warnings.append(warning)
            _print_info(f"    {warning}")

        # ── 5. Select CVEs for YAML (max ~10 per case) ──────────────────
        total_raw_cves = _parse_total_cves(scan_text)
        filtered_parsed, selection_stats = _select_cves(parsed)

        selected_cve_ids: set[str] = set(selection_stats.get("selected_cve_ids", []))
        total_selected = selection_stats["cves_selected"]
        total_found = selection_stats["total_cves_found"]

        _print_info(
            f"    Selected {total_selected}/{total_found} CVEs "
            f"(parsed from scan: {total_raw_cves} total)"
        )

        # ── 6. Filter scan text to only selected CVEs ───────────────────
        if selected_cve_ids:
            filtered_scan_text = _filter_scan_text(scan_text, selected_cve_ids)
        else:
            # No CVEs found (e.g. rabbitmq clean scan) — keep minimal header
            filtered_scan_text = scan_text

        # ── 7. Build TaskCase ───────────────────────────────────────────
        notes_parts: list[str] = []
        if filtered_parsed.get("deployment_summary"):
            notes_parts.append(f"Deployment summary: {filtered_parsed['deployment_summary']}")

        exploitable_count = len(filtered_parsed.get("exploitable_findings", []))
        non_exploitable_count = len(filtered_parsed.get("non_exploitable_findings", []))
        partial_count = len(filtered_parsed.get("partial_findings", []))
        needs_review_count = len(filtered_parsed.get("needs_review", []))
        total = exploitable_count + non_exploitable_count + partial_count + needs_review_count

        source_extras = {
            "total_cves_found": total_found,
            "cves_selected": total_selected,
            "selection_criteria": SELECTION_CRITERIA,
        }

        try:
            task_case = _build_task_case(
                seq=seq,
                stem=stem,
                filtered_scan_text=filtered_scan_text,
                persona_key=persona_key,
                parsed=filtered_parsed,
                notes_parts=notes_parts,
                source_extras=source_extras,
            )
        except ValidationError as exc:
            _print_error(f"{stem}: Pydantic validation failed:\n{exc}")
            return None
        except Exception as exc:
            _print_error(f"{stem}: Failed to build TaskCase: {exc}")
            return None

        # ── 8. Validate via Pydantic (double-check) ─────────────────────
        try:
            _ = task_case.model_validate(task_case.model_dump(mode="python"))
        except ValidationError as exc:
            _print_error(f"{stem}: Re-validation failed:\n{exc}")
            return None

        # ── 9. Serialise to YAML ────────────────────────────────────────
        image_safe = stem
        filename = f"{seq:03d}_{image_safe}_{persona_short}.yaml"
        output_path = OUTPUT_DIR / filename
        yaml_content = _serialise_task_case(task_case)

        # Verify the YAML can be parsed back
        try:
            yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            _print_error(f"{stem}: Generated YAML is invalid:\n{exc}")
            return None

        output_path.write_text(yaml_content, encoding=DEFAULT_ENCODING)
        _print_success(f"  ✓ Saved → {filename}")

        return {
            "seq": seq,
            "filename": filename,
            "display_name": display_name,
            "image": image_name,
            "total": total,
            "total_raw": total_found,
            "cves_selected": total_selected,
            "exploitable": exploitable_count,
            "non_exploitable": non_exploitable_count,
            "partial": partial_count,
            "needs_review": needs_review_count,
            "path": str(output_path),
        }


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


def _print_summary(results: list[dict[str, Any]], warnings: list[str]) -> None:
    """Print a formatted summary table of all generated test cases."""
    if not results:
        _print_info("\nNo test cases were generated.")
        return

    if console and _table_class is not None:
        table = _table_class(
            title="[bold]Trivy Triage — Test Case Generation Summary[/bold]",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("#", justify="right", style="dim")
        table.add_column("File", style="white")
        table.add_column("Persona", style="blue")
        table.add_column("Image", style="yellow")
        table.add_column("Raw CVEs", justify="right")
        table.add_column("Selected", justify="right", style="cyan")
        table.add_column("Expl.", justify="right", style="red")
        table.add_column("N/Expl.", justify="right", style="green")
        table.add_column("Part.", justify="right", style="yellow")
        table.add_column("Rev.", justify="right", style="magenta")

        for r in results:
            table.add_row(
                str(r["seq"]),
                r["filename"],
                r["display_name"],
                r["image"],
                str(r.get("total_raw", r["total"])),
                str(r.get("cves_selected", r["total"])),
                str(r["exploitable"]),
                str(r["non_exploitable"]),
                str(r["partial"]),
                str(r["needs_review"]),
            )

        console.print()
        console.print(table)
    else:
        # Fallback plain-text table
        print("\n" + "=" * 110)
        print("Trivy Triage — Test Case Generation Summary")
        print("=" * 110)
        header = (
            f"{'#':>3}  {'File':<45} {'Persona':<28} {'Img':<18} "
            f"{'Raw':>5} {'Sel.':>4} {'Exp.':>4} {'N/E':>4} {'Part.':>5} {'Rev.':>4}"
        )
        print(header)
        print("-" * 110)
        for r in results:
            print(
                f"{r['seq']:>3}  {r['filename']:<45} {r['display_name']:<28} "
                f"{r['image']:<18} "
                f"{r.get('total_raw', r['total']):>5} "
                f"{r.get('cves_selected', r['total']):>4} "
                f"{r['exploitable']:>4} "
                f"{r['non_exploitable']:>4} "
                f"{r['partial']:>5} "
                f"{r['needs_review']:>4}"
            )
        print("=" * 110)

    totals_raw = sum(r.get("total_raw", r["total"]) for r in results)
    totals_sel = sum(r.get("cves_selected", r["total"]) for r in results)
    totals = {
        "exploitable": sum(r["exploitable"] for r in results),
        "non_exploitable": sum(r["non_exploitable"] for r in results),
        "partial": sum(r["partial"] for r in results),
        "needs_review": sum(r["needs_review"] for r in results),
    }

    if console:
        console.print(
            f"\n[bold]Totals:[/bold] {totals_raw} raw → {totals_sel} selected | "
            f"[red]{totals['exploitable']} exploitable[/red] | "
            f"[green]{totals['non_exploitable']} not exploitable[/green] | "
            f"[yellow]{totals['partial']} partial[/yellow] | "
            f"[magenta]{totals['needs_review']} needs review[/magenta]"
        )
    else:
        print(
            f"\nTotals: {totals_raw} raw → {totals_sel} selected | "
            f"{totals['exploitable']} exploitable | "
            f"{totals['non_exploitable']} not exploitable | "
            f"{totals['partial']} partial | "
            f"{totals['needs_review']} needs review"
        )

    if warnings:
        if console:
            console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for w in warnings:
                console.print(f"  {w}")
        else:
            print("\nWarnings:")
            for w in warnings:
                print(f"  {w}")

    if console:
        console.print(
            f"\n[green]Done.[/green] {len(results)} test case(s) written to "
            f"[bold]{OUTPUT_DIR}[/bold]"
        )
    else:
        print(f"\nDone. {len(results)} test case(s) written to {OUTPUT_DIR}")


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------


async def _main() -> None:
    """Orchestrate the full pipeline."""
    # ── Validate API key ────────────────────────────────────────────────
    api_key = settings.deepseek_api_key
    if not api_key:
        _print_error(
            "DEEPSEEK_API_KEY not set. Add it to ``.env``:\n"
            "  DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        )
        sys.exit(1)

    # ── Ensure output directory exists ──────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Discover scan files ─────────────────────────────────────────────
    scan_files = _discover_scan_files()
    _print_header(f"Found {len(scan_files)} scan file(s) in scans/")

    # ── Compute sequence numbers ────────────────────────────────────────
    next_seq = _compute_next_seq(OUTPUT_DIR)
    _print_info(f"Sequence starts at #{next_seq:03d}")

    # ── Build DeepSeek client ───────────────────────────────────────────
    client = AsyncOpenAI(
        api_key=api_key,
        base_url=DEEPSEEK_BASE_URL,
    )

    # ── Process each scan concurrently (Semaphore-limited) ──────────────
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    warnings: list[str] = []

    tasks = [
        _process_scan(sem, client, scan_path, next_seq + i, warnings)
        for i, scan_path in enumerate(scan_files)
    ]

    results_raw = await asyncio.gather(*tasks)

    # ── Close the HTTP client ───────────────────────────────────────────
    await client.close()

    # ── Collect successful results ─────────────────────────────────────
    results = [r for r in results_raw if r is not None]

    # ── Print summary ───────────────────────────────────────────────────
    _print_summary(results, warnings)

    # Exit with error if nothing was generated
    if not results:
        sys.exit(1)


def main() -> None:
    """Synchronous entrypoint (wraps async main)."""
    asyncio.run(_main())


if __name__ == "__main__":
    main()
