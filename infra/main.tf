# ---------------------------------------------------------------------------
# evalsec dashboard infrastructure: S3 + CloudFront + Route 53 + ACM
# ---------------------------------------------------------------------------
# Architecture:
#   S3 (private) ← Origin Access Control (OAC) ← CloudFront ← Route 53
#
# ACM certificate MUST be in us-east-1 (CloudFront requirement).
# The default provider is ap-southeast-3 (Jakarta).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ACM Certificate (us-east-1: required by CloudFront)
# ---------------------------------------------------------------------------
resource "aws_acm_certificate" "dashboard" {
  provider          = aws.us_east_1
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

# # ---------------------------------------------------------------------------
# # Route 53 Hosted Zone (disabled: using Cloudflare instead)
# # ---------------------------------------------------------------------------
# data "aws_route53_zone" "main" {
#   name         = var.domain_name
#   private_zone = false
# }

# # DNS validation records for ACM certificate (disabled: Cloudflare)
# resource "aws_route53_record" "cert_validation" {
#   for_each = {
#     for dvo in aws_acm_certificate.dashboard.domain_validation_options : dvo.domain_name => {
#       name   = dvo.resource_record_name
#       record = dvo.resource_record_value
#       type   = dvo.resource_record_type
#     }
#   }
#
#   allow_overwrite = true
#   name            = each.value.name
#   records         = [each.value.record]
#   ttl             = 60
#   type            = each.value.type
#   zone_id         = data.aws_route53_zone.main.zone_id
# }

# # ACM certificate validation (disabled: manual via Cloudflare DNS)
# resource "aws_acm_certificate_validation" "dashboard" {
#   provider                = aws.us_east_1
#   certificate_arn         = aws_acm_certificate.dashboard.arn
#   validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
# }

# ---------------------------------------------------------------------------
# S3 Bucket (private: no public access)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "dashboard" {
  bucket = var.s3_bucket_name != "" ? var.s3_bucket_name : null
  # If bucket_name is empty, Terraform generates a unique name

  tags = var.tags
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Disable ACLs (required for OAC)
resource "aws_s3_bucket_ownership_controls" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Enable S3 static website hosting (redirects handled by CloudFront)
resource "aws_s3_bucket_website_configuration" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"
  }
}

# ---------------------------------------------------------------------------
# CloudFront Origin Access Control (OAC)
# ---------------------------------------------------------------------------
resource "aws_cloudfront_origin_access_control" "dashboard" {
  name                              = "evalsec-dashboard-oac"
  description                       = "OAC for evalsec dashboard S3 bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# ---------------------------------------------------------------------------
# S3 bucket policy: grants s3:GetObject only to the specific CloudFront
# distribution via Origin Access Control
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_policy" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  # NOTE: The CloudFront distribution must exist first so we can reference
  # its ARN in the policy. We use depends_on to ensure ordering.
  policy = data.aws_iam_policy_document.dashboard_bucket_policy.json
}

data "aws_iam_policy_document" "dashboard_bucket_policy" {
  statement {
    sid    = "AllowCloudFrontOAC"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.dashboard.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.dashboard.arn]
    }
  }
}

# ---------------------------------------------------------------------------
# CloudFront Distribution
# ---------------------------------------------------------------------------
resource "aws_cloudfront_distribution" "dashboard" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "evalsec dashboard: ${var.domain_name}"
  default_root_object = "index.html"
  price_class         = var.cloudfront_price_class

  aliases = [var.domain_name]

  # SSL certificate (must be in us-east-1)
  # Use var.acm_certificate_arn if provided (pre-validated), otherwise create one
  viewer_certificate {
    acm_certificate_arn      = var.acm_certificate_arn != "" ? var.acm_certificate_arn : aws_acm_certificate.dashboard.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  # Custom error response: SPA-style, serve index.html on 404
  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  # Origin: S3 bucket
  origin {
    domain_name              = aws_s3_bucket.dashboard.bucket_regional_domain_name
    origin_id                = "s3-dashboard"
    origin_access_control_id = aws_cloudfront_origin_access_control.dashboard.id
  }

  # Default cache behavior (index.html: short TTL for fast iteration)
  default_cache_behavior {
    target_origin_id = "s3-dashboard"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD", "OPTIONS"]

    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    # Short TTL for index.html: deploy updates quickly
    min_ttl     = 0
    default_ttl = var.index_ttl_seconds
    max_ttl     = var.index_ttl_seconds * 2

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  # Ordered cache behavior: hashed assets (long TTL)
  ordered_cache_behavior {
    path_pattern     = "assets/*"
    target_origin_id = "s3-dashboard"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD", "OPTIONS"]

    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    # Long TTL for hashed assets: they never change
    min_ttl     = 0
    default_ttl = var.static_ttl_seconds
    max_ttl     = var.static_ttl_seconds

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = var.tags
}

# # ---------------------------------------------------------------------------
# # Route 53 DNS record pointing to CloudFront (disabled: Cloudflare CNAME)
# # ---------------------------------------------------------------------------
# resource "aws_route53_record" "dashboard" {
#   zone_id = data.aws_route53_zone.main.zone_id
#   name    = var.domain_name
#   type    = "A"
#
#   alias {
#     name                   = aws_cloudfront_distribution.dashboard.domain_name
#     zone_id                = aws_cloudfront_distribution.dashboard.hosted_zone_id
#     evaluate_target_health = false
#   }
# }
