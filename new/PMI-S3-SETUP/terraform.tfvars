bucket_name = "your-bucket-name"
tags = {
  Environment = "your-environment"
  Project     = "PMI-S3-SETUP"
}
attach_policy = true
attach_deny_insecure_transport_policy = true
attach_require_latest_tls_policy = true
allowed_kms_key_arn = "arn:aws:kms:your-region:your-account-id:key/your-key-id"
attach_deny_unencrypted_object_uploads = true
control_object_ownership = true
object_ownership = "BucketOwnerPreferred"
transition_default_minimum_object_size = 128
acl = "private"
versioning = {
  enabled = true
}
website = {
  index_document = "index.html"
  error_document = "error.html"
}
kms_key_arn = "arn:aws:kms:your-region:your-account-id:key/your-key-id"
cors_rule = [
  {
    allowed_methods = ["GET", "PUT"]
    allowed_origins = ["*"]
    allowed_headers = ["*"]
    expose_headers  = []
    max_age_seconds = 3000
  }
]
lifecycle_rule = [
  {
    id      = "lifecycle-rule"
    enabled = true
    expiration = {
      days = 365
    }
  }
]
intelligent_tiering = true
metric_configuration = {
  id = "metrics"
  filter = {
    prefix = ""
    tags = {
      "key" = "value"
    }
  }
}
log_bucket_name = "your-log-bucket-name"
days = 30