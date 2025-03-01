# Region setting for the bucket
region = "us-east-1"

# Bucket name
bucket_name = "854473044844-mti-testing-bkt"


#s3 access loging (do not change this section however make sure the bucket name match the environmnet you want to peovision in)
log_bucket_name = "854473044844-mti-logs-test"


# Tags associated with the bucket
tags = {
  Nanme       = "mti-testing-bkt"
  Environment = "Production"                        #
  Project     = "StaticSiteHosting"
  Team        = "WebOps"
  Contact     = "DevOps-Team"
  Application = "Website Hosting"
  CostCenter  = "12345"
  Compliance  = "PCI-DSS"
  Service     = "S3"
  ManagedBy   = "Terraform"
}

# Control object ownership setting
control_object_ownership = true

# Object ownership configuration
object_ownership         = "BucketOwnerPreferred"

# Default minimum object size for transition by storage class
transition_default_minimum_object_size = "varies_by_storage_class"

# Access control list setting
acl = "private" 

# KMS Key ARN for encryption (if any) Default is "AES256"  (aws managed key)
kms_key_arn = "AES256"


# Versioning configuration for the bucket
versioning = {
  status     = "Enabled"
  mfa_delete = "Disabled"  # Change from "Enabled" to "Disabled"
}

# Website configuration for the bucket
website = {

  index_document = "index.html"
  error_document = "error.html"
  routing_rules = [{
    condition = {
      key_prefix_equals = "docs/"
    },
    redirect = {
      replace_key_prefix_with = "documents/"
    }
    }, {
    condition = {
      http_error_code_returned_equals = 404
      key_prefix_equals               = "archive/"
    },
    redirect = {
      host_name          = "archive.myhost.com"
      http_redirect_code = 301
      protocol           = "https"
      replace_key_with   = "not_found.html"
    }
  }]
}


# server_side_encryption_configuration    

# server_side_encryption_configuration = {
#   rule = [{
#     bucket_key_enabled = true
#     apply_server_side_encryption_by_default = {
#       sse_algorithm     = "AES256"
#       kms_master_key_id = null
#     }
#   }]
# }


#If you want to use a custom KMS key, modify terraform.tfvars like this:
# server_side_encryption_configuration = {
#   rule = [{
#     bucket_key_enabled = true
#     apply_server_side_encryption_by_default = {
#       sse_algorithm     = "aws:kms"
#       kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/my-custom-key"
#     }
#   }]
# }


# CORS rules configuration for the bucket
cors_rule = [
  {
    allowed_methods = ["PUT", "POST"]
    allowed_origins = ["https://modules.tf", "https://terraform-aws-modules.modules.tf"]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
    }, {
    allowed_methods = ["PUT"]
    allowed_origins = ["https://example.com"]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
]

# Lifecycle rules configuration for the bucket
lifecycle_rule = [
  {
    id      = "log"
    enabled = false

    filter = {
      tags = {
        some    = "value"
        another = "value2"
      }
    }

    transition = [
      {
        days          = 30
        storage_class = "ONEZONE_IA"
        }, {
        days          = 60
        storage_class = "GLACIER"
      }
    ]
  },
  {
    id                                     = "log1"
    enabled                                = false
    abort_incomplete_multipart_upload_days = 7

    noncurrent_version_transition = [
      {
        days          = 30
        storage_class = "STANDARD_IA"
      },
      {
        days          = 60
        storage_class = "ONEZONE_IA"
      },
      {
        days          = 90
        storage_class = "GLACIER"
      },
    ]

    noncurrent_version_expiration = {
      days = 300
    }
  },
  {
    id      = "log2"
    enabled = false

    filter = {
      prefix                   = "log1/"
      object_size_greater_than = 200000
      object_size_less_than    = 500000
      tags = {
        some    = "value"
        another = "value2"
      }
    }

    noncurrent_version_transition = [
      {
        days          = 30
        storage_class = "STANDARD_IA"
      },
    ]

    noncurrent_version_expiration = {
      days = 300
    }
  },
]

# Intelligent tiering configuration for the bucket
intelligent_tiering = {
  general = {
    status = "Enabled"
    filter = {
      prefix = "/"
      tags = {
        Environment = "dev"
      }
    }
    tiering = {
      ARCHIVE_ACCESS = {
        days = 180
      }
    }
  },
  documents = {
    status = false
    filter = {
      prefix = "documents/"
    }
    tiering = {
      ARCHIVE_ACCESS = {
        days = 125
      }
      DEEP_ARCHIVE_ACCESS = {
        days = 200
      }
    }
  }
}

# Metric configuration for the bucket
metric_configuration = [
  {
    name = "documents"
    filter = {
      prefix = "documents/"
      tags = {
        priority = "high"
      }
    }
  },
  {
    name = "other"
    filter = {
      tags = {
        production = "true"
      }
    }
  },
  {
    name = "all"
  }
]
