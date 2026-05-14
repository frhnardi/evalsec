# ---------------------------------------------------------------------------
# Variables for evalsec infrastructure
# ---------------------------------------------------------------------------

variable "domain_name" {
  description = "The domain name for the dashboard (e.g., dashboard.evalsec.example.com)"
  type        = string
}

variable "github_owner" {
  description = "GitHub repository owner (e.g., frhnardi)"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name (e.g., evalsec)"
  type        = string
}

variable "github_branch" {
  description = "GitHub branch allowed to deploy via OIDC (default: main)"
  type        = string
  default     = "main"
}

variable "s3_bucket_name" {
  description = "Optional: override the auto-generated S3 bucket name. If empty, Terraform generates one."
  type        = string
  default     = ""
}

variable "cloudfront_price_class" {
  description = "CloudFront price class: PriceClass_All, PriceClass_200, or PriceClass_100"
  type        = string
  default     = "PriceClass_100"
}

variable "index_ttl_seconds" {
  description = "CloudFront TTL for index.html (default: 60s for fast iteration)"
  type        = number
  default     = 60
}

variable "static_ttl_seconds" {
  description = "CloudFront TTL for hashed static assets (default: 1 year)"
  type        = number
  default     = 31536000
}

variable "acm_certificate_arn" {
  description = "ARN of an existing ACM certificate (us-east-1) for the CloudFront custom domain. If empty, Terraform creates one (but it must be validated manually via Cloudflare DNS before CloudFront can use it)."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "evalsec"
    ManagedBy   = "terraform"
    Environment = "production"
  }
}
