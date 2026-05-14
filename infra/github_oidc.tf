# ---------------------------------------------------------------------------
# GitHub Actions OIDC — IAM role with minimum permissions
# ---------------------------------------------------------------------------
# Allows GitHub Actions (from the specified repo + branch) to:
#   - Upload files to the dashboard S3 bucket
#   - Create CloudFront invalidations
#
# Trust policy constrains by repo AND branch (no wildcards).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# IAM OIDC Identity Provider for GitHub Actions
# ---------------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com",
  ]

  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
  ]
}

# ---------------------------------------------------------------------------
# IAM Role — assumed by GitHub Actions
# ---------------------------------------------------------------------------
resource "aws_iam_role" "github_actions" {
  name               = "evalsec-github-actions"
  assume_role_policy = data.aws_iam_policy_document.github_actions_trust.json

  tags = var.tags
}

# Trust policy — constrain by repo AND branch
data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    sid    = "GitHubActionsOIDC"
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/${var.github_branch}",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# IAM Policy — minimum permissions for deployment
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "github_actions_deploy" {
  name        = "evalsec-deploy"
  description = "Minimum permissions for evalsec GitHub Actions deployment"
  policy      = data.aws_iam_policy_document.github_actions_deploy.json

  tags = var.tags
}

data "aws_iam_policy_document" "github_actions_deploy" {
  # s3:ListBucket on the bucket itself (needed for `aws s3 sync`)
  statement {
    sid    = "S3ListBucket"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.dashboard.arn,
    ]
  }

  # s3:PutObject + s3:DeleteObject on objects inside the bucket
  statement {
    sid    = "S3UploadAndDelete"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = [
      "${aws_s3_bucket.dashboard.arn}/*",
    ]
  }

  # cloudfront:CreateInvalidation on the specific distribution
  statement {
    sid    = "CloudFrontInvalidation"
    effect = "Allow"
    actions = [
      "cloudfront:CreateInvalidation",
    ]
    resources = [
      aws_cloudfront_distribution.dashboard.arn,
    ]
  }
}

# ---------------------------------------------------------------------------
# Attach the policy to the role
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy_attachment" "github_actions_deploy" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions_deploy.arn
}
