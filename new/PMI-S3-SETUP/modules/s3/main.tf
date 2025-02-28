resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  acl    = var.acl

  versioning {
    enabled = var.versioning
  }

  website {
    index_document = var.website.index_document
    error_document = var.website.error_document
  }

  logging {
    target_bucket = var.log_bucket_name
    target_prefix = "${var.bucket_name}/logs/"
  }

  lifecycle_rule {
    id      = "lifecycle_rule"
    enabled = true

    transition {
      days          = var.transition_default_minimum_object_size
      storage_class = "GLACIER"
    }
  }

  cors_rule {
    allowed_methods = var.cors_rule.allowed_methods
    allowed_origins = var.cors_rule.allowed_origins
    allowed_headers = var.cors_rule.allowed_headers
    expose_headers  = var.cors_rule.expose_headers
    max_age_seconds = var.cors_rule.max_age_seconds
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = var.tags
}

output "bucket_id" {
  value = aws_s3_bucket.this.id
}

output "bucket_arn" {
  value = aws_s3_bucket.this.arn
}