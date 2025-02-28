locals {
  bucket_name = var.bucket_name
}

data "aws_caller_identity" "current" {}

data "aws_canonical_user_id" "current" {}

data "aws_cloudfront_log_delivery_canonical_user_id" "cloudfront" {}

module "s3_bucket" {
  source = "../../modules/s3"

  bucket = local.bucket_name

  force_destroy       = true
  acceleration_status = "Suspended"
  request_payer       = "BucketOwner"

  tags = var.tags

  object_lock_enabled = true
  object_lock_configuration = {
    rule = {
      default_retention = {
        mode = "GOVERNANCE"
        days = var.days
      }
    }
  }

  attach_policy                            = var.attach_policy
  policy                                   = file("${path.module}/policy/policy.json")
  attach_deny_insecure_transport_policy    = var.attach_deny_insecure_transport_policy
  attach_require_latest_tls_policy         = var.attach_require_latest_tls_policy
  allowed_kms_key_arn                      = var.allowed_kms_key_arn
  attach_deny_unencrypted_object_uploads   = var.attach_deny_unencrypted_object_uploads

  control_object_ownership = var.control_object_ownership
  object_ownership         = var.object_ownership

  expected_bucket_owner                  = data.aws_caller_identity.current.account_id
  transition_default_minimum_object_size = var.transition_default_minimum_object_size

  acl = var.acl

  versioning = var.versioning

  website = var.website
  kms_key_arn = var.kms_key_arn

  cors_rule = var.cors_rule

  lifecycle_rule = var.lifecycle_rule

  intelligent_tiering = var.intelligent_tiering

  metric_configuration = var.metric_configuration

  logging = {
    target_bucket = var.log_bucket_name
    target_prefix = "${var.bucket_name}/logs/"
  }
}