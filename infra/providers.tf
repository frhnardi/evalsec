# ---------------------------------------------------------------------------
# Terraform providers for evalsec infrastructure
# ---------------------------------------------------------------------------
# Default provider: ap-southeast-3 (Jakarta region: principal workload)
# Aliased provider: us-east-1 (required by CloudFront for ACM certificates)
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.9, < 2"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 6"
    }
  }
}

provider "aws" {
  region = "ap-southeast-3"
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
