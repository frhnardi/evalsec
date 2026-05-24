# ---------------------------------------------------------------------------
# Outputs: values to set as GitHub Actions Secrets / variables
# ---------------------------------------------------------------------------

output "s3_bucket_name" {
  description = "S3 bucket name for the dashboard (set as GH Actions variable)"
  value       = aws_s3_bucket.dashboard.id
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (set as GH Actions variable)"
  value       = aws_cloudfront_distribution.dashboard.id
}

output "cloudfront_domain_name" {
  description = "CloudFront domain name (for Route 53 alias target)"
  value       = aws_cloudfront_distribution.dashboard.domain_name
}

output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions OIDC (set as GH Actions secret)"
  value       = aws_iam_role.github_actions.arn
}

output "acm_certificate_arn" {
  description = "ACM certificate ARN (us-east-1)"
  value       = aws_acm_certificate.dashboard.arn
}

output "dashboard_url" {
  description = "Public URL of the evalsec dashboard"
  value       = "https://${var.domain_name}"
}
