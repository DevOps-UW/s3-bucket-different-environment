locals {
  bucket_name = "mti-bucket"
}

module "s3_bucket" {
  source = "../../modules/s3"

  bucket = local.bucket_name

  force_destroy       = true
  acceleration_status = "Suspended"
  request_payer       = "BucketOwner"

  tags = {
    Environment = "MTI"
    Project     = "PMI-S3-Setup"
  }

  object_lock_enabled = true
  object_lock_configuration = {
    rule = {
      default_retention = {
        mode = "GOVERNANCE"
        days = 30
      }
    }
  }

  attach_policy                            = true
  policy                                   = file("${path.module}/policy/policy.json")
  attach_deny_insecure_transport_policy    = true
  attach_require_latest_tls_policy         = true
  allowed_kms_key_arn                      = var.allowed_kms_key_arn
  attach_deny_unencrypted_object_uploads   = true

  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"

  expected_bucket_owner                  = data.aws_caller_identity.current.account_id
  transition_default_minimum_object_size = 0

  acl = "private"

  versioning = {
    enabled = true
  }

  website = {
    index_document = "index.html"
    error_document = "error.html"
  }
  
  kms_key_arn = var.kms_key_arn

  cors_rule = var.cors_rule

  lifecycle_rule = var.lifecycle_rule

  intelligent_tiering = var.intelligent_tiering

  metric_configuration = var.metric_configuration

  logging = {
    target_bucket = var.log_bucket_name
    target_prefix = "${local.bucket_name}/logs/"
  }
}