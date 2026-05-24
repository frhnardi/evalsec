# evalsec: AWS Infrastructure

This directory contains Terraform configurations for the evalsec dashboard
infrastructure: S3 (private) → CloudFront (CDN) → DNS via Cloudflare.

## Architecture

```
User ──► Cloudflare (CNAME) ──► CloudFront ──► S3 (private, via OAC)
```

- **S3 bucket**: Private. No public access. CloudFront accesses via OAC.
- **CloudFront**: CDN with custom domain, HTTPS, short TTL on `index.html` (60s),
  long TTL on hashed assets (1 year).
- **ACM**: Certificate in `us-east-1` (required by CloudFront). Validation is
  done **manually via Cloudflare DNS** (CNAME records).
- **DNS**: Managed via **Cloudflare Dashboard** (not Route 53). You create a
  CNAME record pointing to the CloudFront distribution domain.
- **OIDC**: GitHub Actions can deploy via IAM role with minimum permissions
  (only `s3:PutObject`, `s3:DeleteObject`, `cloudfront:CreateInvalidation`).

## Prerequisites

1. **AWS CLI** configured with credentials that can create all resources.
2. **Terraform** >= 1.9.
3. **Cloudflare account** with your domain (`farhan.ngenz.org`) added.
4. **GitHub repository** already created.

## Quick Start

```bash
# 1. Change into the infra directory
cd infra

# 2. Initialise Terraform
terraform init

# 3. Review the plan
terraform plan \
  -var="domain_name=dashboard.evalsec.farhan.ngenz.org" \
  -var="github_owner=frhnardi" \
  -var="github_repo=evalsec"

# 4. If the plan looks correct, apply
terraform apply \
  -var="domain_name=dashboard.evalsec.farhan.ngenz.org" \
  -var="github_owner=frhnardi" \
  -var="github_repo=evalsec"
```

## After Apply: Manual DNS via Cloudflare

Terraform creates the ACM certificate and CloudFront distribution, but Route 53
blocks are **disabled** (commented out). You must validate the certificate and
set up DNS manually:

### Step 1: Get CloudFront domain name

```bash
terraform output cloudfront_domain_name
# → d123.cloudfront.net
```

### Step 2: Validate ACM Certificate

1. Go to **AWS Console → Certificate Manager** (us-east-1 region)
2. Find the certificate for `dashboard.evalsec.farhan.ngenz.org`
3. Expand **Domain validation records**: you'll see CNAME records like:
   ```
   _xxx.dashboard.evalsec.farhan.ngenz.org → _yyy.acm-validations.aws
   ```
4. In **Cloudflare Dashboard** → your domain → DNS → **Add Record**:
   - Type: `CNAME`
   - Name: `_xxx.dashboard.evalsec` (from ACM)
   - Target: `_yyy.acm-validations.aws`
   - Proxy status: **DNS only** (grey cloud, ❌ orange)

After a few minutes, the certificate status changes to **Issued**.

### Step 3: Create DNS record for dashboard

In **Cloudflare Dashboard** → DNS → **Add Record**:

| Field | Value |
|-------|-------|
| Type | `CNAME` |
| Name | `dashboard` |
| Target | `<cloudfront-domain>.cloudfront.net` (from `terraform output`) |
| Proxy status | **DNS only** (grey cloud, ❌ orange) |

> **⚠️ Important:** Proxy (orange cloud) must be **OFF**. CloudFront uses its own
> SSL certificate (ACM), so enabling Cloudflare proxy causes SSL conflicts.

### Step 4: Set GitHub Actions variables

After `terraform apply`, capture these outputs:

| Command | Set As |
|---------|--------|
| `terraform output s3_bucket_name` | Actions variable `S3_BUCKET` |
| `terraform output cloudfront_distribution_id` | Actions variable `CF_DISTRIBUTION_ID` |
| `terraform output github_actions_role_arn` | Actions secret `AWS_ROLE_ARN` |

Also set:
- `AWS_REGION` → `ap-southeast-3`
- `DOMAIN_NAME` → `dashboard.evalsec.farhan.ngenz.org`

### Step 5: Verify OIDC

1. Go to IAM role `evalsec-github-actions` in AWS Console
2. Verify the trust policy allows your repo:branch
3. Set `AWS_ROLE_ARN` in GitHub repo → Settings → Secrets and variables → Actions

## Variables

| Variable | Default | Description |
|---|---|---|
| `domain_name` | (required) | Dashboard domain (e.g., `dashboard.evalsec.ngenz.org`) |
| `github_owner` | (required) | GitHub org/user (e.g., `frhnardi`) |
| `github_repo` | (required) | GitHub repo name (e.g., `evalsec`) |
| `github_branch` | `main` | Branch allowed to deploy via OIDC |
| `acm_certificate_arn` | `""` | **Recommended:** ARN of a pre-validated ACM certificate (us-east-1). If empty, Terraform creates one but CloudFront creation will fail until the cert is validated manually. |
| `s3_bucket_name` | auto-generated | Override bucket name if needed |
| `cloudfront_price_class` | `PriceClass_100` | CloudFront price class |
| `index_ttl_seconds` | `60` | TTL for `index.html` |
| `static_ttl_seconds` | `31536000` | TTL for hashed assets (1 year) |

## Cost Estimate

Rough monthly costs (us-east-1 + ap-southeast-3, PriceClass_100):

| Resource | Monthly Cost |
|---|---|
| S3 (1 GB, minimal requests) | < $0.05 |
| CloudFront (1 GB egress, PriceClass_100) | ~ $0.85 |
| ACM (no cost) | $0.00 |
| **Total** | **~ $0.90/month** |

> Note: No Route 53 cost since DNS is via Cloudflare (free tier).

## Cleanup

```bash
terraform destroy \
  -var="domain_name=dashboard.evalsec.farhan.ngenz.org" \
  -var="github_owner=frhnardi" \
  -var="github_repo=evalsec"
```

> **Note**: The S3 bucket must be empty before Terraform can destroy it.
> Delete all objects first via AWS Console or `aws s3 rm s3://BUCKET --recursive`.
> Also remove the CNAME records from Cloudflare after destroy.
