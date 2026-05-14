Saya punya 8 test cases di tests/data/trivy_triage/ sekarang
(002-009). Saya ingin extend dataset ke 17 total cases dengan
menambah 9 cases baru (010-018) untuk variasi kategori yang
saat ini masih missing.

CONTEXT - cases yang sudah ada:
- 002 redis (internal cache)
- 003 mysql (read replica)  
- 004 nginx (public web)
- 005 postgres (primary DB)
- 006 python (ML inference)
- 007 rabbitmq (message broker)
- 008 grafana (monitoring)
- 009 tomcat (legacy with security debt)

GAP yang harus diisi dengan 9 cases baru:

─────────────────────────────────────────────────────────────
CASE 010 — node:18 (JS/Node.js API service)
─────────────────────────────────────────────────────────────
Image: node:18
Persona: "Node.js Express REST API on EKS, namespace: api-services.
ClusterIP service, NetworkPolicy ingress dari frontend namespace only.
Restricted PSS, runAsNonRoot uid 1000, readOnlyRootFilesystem with
emptyDir for /tmp, capabilities drop ALL. Uses Express, lodash,
axios, jsonwebtoken. devDependencies (jest, eslint) installed
in image but NEVER invoked at runtime. Stores customer auth tokens
in memory. UU PDP scope."
Highlight: model must distinguish devDependencies CVEs (lower risk
since not invoked) vs production dependencies CVEs.

─────────────────────────────────────────────────────────────
CASE 011 — alpine:3.14 (minimal base image)
─────────────────────────────────────────────────────────────
Image: alpine:3.14
Persona: "Empty Alpine base image being evaluated for use as base
for new microservices. Not yet deployed — security review phase.
Will be deployed with: restricted PSS, runAsNonRoot, no shell
access in production, IRSA for AWS API access."
Highlight: this is hallucination resistance test — model should
NOT invent vulnerabilities not in scan. Minimal CVE count tests
whether model can give "low risk, proceed" verdict without
exaggerating threats.

─────────────────────────────────────────────────────────────
CASE 012 — elasticsearch:7.10 (search backend)
─────────────────────────────────────────────────────────────
Image: elasticsearch:7.10
Persona: "Elasticsearch 7.10 cluster on EKS, namespace: search.
Used as full-text search backend for fintech product catalog.
ClusterIP service, NetworkPolicy from api-services namespace only.
Pod Security baseline (needs vm.max_map_count sysctl).
X-Pack security enabled with basic auth, but TLS NOT yet configured
on transport layer (known gap, ticket #1023). Stores
non-PII product data, but credentials in cluster state. PCI-DSS
adjacent (queries reference card brand mapping)."
Highlight: known security debt scenario, mixed PII risk.

─────────────────────────────────────────────────────────────
CASE 013 — prometheus:2.30 (metrics scraper)
─────────────────────────────────────────────────────────────
Image: prom/prometheus:v2.30.0
Persona: "Prometheus on EKS, namespace: monitoring. Scrapes metrics
from all namespaces. Service mesh: Istio with mTLS STRICT mode
enabled cluster-wide. Pod identity via SPIFFE/IRSA. ClusterIP
service, accessible via Grafana ingress only. No PII in metrics,
but metric labels may contain internal service topology."
Highlight: mTLS via service mesh as mitigation — model should
recognize that some network-vector CVEs are mitigated by mesh.

─────────────────────────────────────────────────────────────
CASE 014 — ghost:4 (CMS public blog)
─────────────────────────────────────────────────────────────
Image: ghost:4
Persona: "Ghost CMS for company engineering blog. Public-facing via
ALB + CloudFront. No customer data, but admin panel can deploy
arbitrary content. Authentication: SSO via Auth0 for admin panel.
NetworkPolicy: ingress from ALB only. Not OJK-supervised (marketing
site only)."
Highlight: lower-stakes public service, model should NOT over-react
to severity scores given non-financial scope. Tests contextual
risk calibration.

─────────────────────────────────────────────────────────────
CASE 015 — wordpress:5.7 (multi-tenant SaaS)
─────────────────────────────────────────────────────────────
Image: wordpress:5.7
Persona: "WordPress multi-tenant SaaS hosting 200+ customer sites.
Layered defense: AWS WAF on ALB with OWASP rules + ModSecurity in
nginx sidecar + Wordfence plugin. Stores customer PII (names,
emails, billing). PCI-DSS scope for billing pages. NetworkPolicy
allows public ingress via ALB. Database is RDS Aurora separate
from container. UU PDP scope."
Highlight: layered defense — model should reason about WAF + ModSec +
plugin combined coverage, not just patch every CVE immediately.

─────────────────────────────────────────────────────────────
CASE 016 — vault:1.8 (secrets manager)
─────────────────────────────────────────────────────────────
Image: hashicorp/vault:1.8
Persona: "HashiCorp Vault on EKS, namespace: security. Manages
secrets for all microservices via Vault Agent injector pattern.
ClusterIP only, accessed via Kubernetes auth method. Storage backend:
Consul on separate cluster. TLS enabled with internal CA. Audit
log to encrypted S3. Critical infrastructure — compromise = total
secrets disclosure for entire platform. OJK-supervised."
Highlight: critical infrastructure where CVE severity must be
amplified — model should treat any auth bypass as P0.

─────────────────────────────────────────────────────────────
CASE 017 — ubuntu:18.04 (base image edge case)
─────────────────────────────────────────────────────────────
Image: ubuntu:18.04
Persona: "Ubuntu 18.04 base image used in legacy build pipeline.
NOT deployed to production — only used for CI/CD builds. Container
runs in GitHub Actions runner, isolated from production environment.
Compiled artifacts copied to fresh distroless image for prod."
Highlight: build-time vs runtime distinction. Many CVEs irrelevant
because container never reaches production. Tests whether model
understands deployment lifecycle context.

─────────────────────────────────────────────────────────────
CASE 018 — golang:1.16 (build-time toolchain)
─────────────────────────────────────────────────────────────
Image: golang:1.16
Persona: "Golang 1.16 toolchain in CI/CD build environment. Used to
compile Go microservices, final binaries deployed via distroless.
Builder image NEVER runs in production. Build runs in GitHub
Actions ephemeral runner with restricted token, isolated from
production AWS account."
Highlight: same lifecycle question as case 017, but Go-specific
(go.sum, vendored deps). Model must reason that toolchain CVEs
don't affect compiled artifact security.

─────────────────────────────────────────────────────────────
EXECUTION:
─────────────────────────────────────────────────────────────
1. Scan semua 9 images:
   for img in "node:18" "alpine:3.14" "elasticsearch:7.10" \
              "prom/prometheus:v2.30.0" "ghost:4" "wordpress:5.7" \
              "hashicorp/vault:1.8" "ubuntu:18.04" "golang:1.16"; do
     safe=$(echo $img | tr ':/' '__')
     trivy image --severity HIGH,CRITICAL "$img" > "scans/${safe}.txt"
   done

2. Update scripts/generate_cases.py:
   - Tambah persona mapping untuk 9 cases baru di atas
   - Set starting sequence number ke 010
   - JANGAN regenerate cases 002-009 yang sudah ada
   - Filter mapping berdasarkan filename pattern:
     node_*       → persona node
     alpine_*     → persona alpine
     elasticsearch_* → persona elasticsearch
     prometheus_* atau prom_*  → persona prometheus
     ghost_*      → persona ghost
     wordpress_*  → persona wordpress
     vault_* atau hashicorp_* → persona vault
     ubuntu_*     → persona ubuntu (build-time)
     golang_*     → persona golang (build-time)

3. Run generator hanya untuk scan files baru:
   uv run python scripts/generate_cases.py
   (script should skip files that already have corresponding YAML)

4. Validate semua 17 YAML files:
   uv run python scripts/validate_yaml.py tests/data/trivy_triage/

5. Print summary: berapa cases generated, berapa CVE per case,
   cases mana yang punya >40% needs_review flag

REQUIREMENTS:
- Same trimming logic (max 10 CVE per case, prioritize mix of
  exploitable + non-exploitable + partial)
- Same source.type = "ai_assisted_deepseek_v4"
- Same Pydantic validation
- DO NOT regenerate cases 002-009 yang sudah ada — skip kalau
  YAML file dengan sequence number sama sudah ada

One file response (update ke generate_cases.py),
tunggu konfirmasi sebelum execute.