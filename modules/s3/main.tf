data "aws_region" "current" {}

data "aws_canonical_user_id" "this" {
  count = local.create_bucket && local.create_bucket_acl && try(var.owner["id"], null) == null ? 1 : 0
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
locals {
  enable_bucket_key = true
  sse_s3_algorithm  = "AES256"
  sse_kms_algorithm = "aws:kms"

  sse_algorithm     = var.kms_key_arn == "" ? local.sse_s3_algorithm : local.sse_kms_algorithm
  kms_master_key_id = var.kms_key_arn == "" ? null : var.kms_key_arn
  create_bucket     = var.create_bucket

  create_bucket_acl = (var.acl != null && var.acl != "null") || length(local.grants) > 0

  attach_policy = var.attach_require_latest_tls_policy || var.attach_access_log_delivery_policy || var.attach_elb_log_delivery_policy || var.attach_lb_log_delivery_policy || var.attach_deny_insecure_transport_policy || var.attach_deny_unencrypted_object_uploads || var.attach_policy

  # Variables with type `any` should be jsonencode()'d when value is coming from Terragrunt
  grants               = try(jsondecode(var.grant), var.grant)
  cors_rules           = try(jsondecode(var.cors_rule), var.cors_rule)
  lifecycle_rules      = try(jsondecode(var.lifecycle_rule), var.lifecycle_rule)
  intelligent_tiering  = try(jsondecode(var.intelligent_tiering), var.intelligent_tiering)
  metric_configuration = try(jsondecode(var.metric_configuration), var.metric_configuration)
}

resource "aws_s3_bucket" "this" {
  count = local.create_bucket ? 1 : 0

  bucket        = var.bucket
  bucket_prefix = var.bucket_prefix

  force_destroy       = var.force_destroy
  object_lock_enabled = var.object_lock_enabled
  tags                = var.tags
}

resource "aws_s3_bucket_logging" "this" {
  count = local.create_bucket && length(keys(var.logging)) > 0 ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  target_bucket = var.logging["target_bucket"]
  target_prefix = var.logging["target_prefix"]

  # dynamic "target_object_key_format" {
  #   for_each = try([var.logging["target_object_key_format"]], [])

  #   content {
  #     dynamic "partitioned_prefix" {
  #       for_each = try(target_object_key_format.value["partitioned_prefix"], [])

  #       content {
  #         partition_date_source = try(partitioned_prefix.value, null)
  #       }
  #     }

  #     dynamic "simple_prefix" {
  #       for_each = length(try(target_object_key_format.value["partitioned_prefix"], [])) == 0 || can(target_object_key_format.value["simple_prefix"]) ? [true] : []

  #       content {}
  #     }
  #   }
  # }
}

resource "aws_s3_bucket_acl" "this" {
  count = local.create_bucket && local.create_bucket_acl ? 1 : 0

  bucket                = aws_s3_bucket.this[0].id
  expected_bucket_owner = var.expected_bucket_owner

  # hack when `null` value can't be used (eg, from terragrunt, https://github.com/gruntwork-io/terragrunt/pull/1367)
  acl = var.acl == "null" ? null : var.acl

  dynamic "access_control_policy" {
    for_each = length(local.grants) > 0 ? [true] : []

    content {
      dynamic "grant" {
        for_each = local.grants

        content {
          permission = grant.value.permission

          grantee {
            type          = grant.value.type
            id            = try(grant.value.id, null)
            uri           = try(grant.value.uri, null)
            email_address = try(grant.value.email, null)
          }
        }
      }

      owner {
        id           = try(var.owner["id"], data.aws_canonical_user_id.this[0].id)
        display_name = try(var.owner["display_name"], null)
      }
    }
  }

  # This `depends_on` is to prevent "AccessControlListNotSupported: The bucket does not allow ACLs."
  depends_on = [aws_s3_bucket_ownership_controls.this]
}

resource "aws_s3_bucket_website_configuration" "this" {
  count = local.create_bucket && length(keys(var.website)) > 0 ? 1 : 0

  bucket                = aws_s3_bucket.this[0].id
  expected_bucket_owner = var.expected_bucket_owner

  dynamic "index_document" {
    for_each = try([var.website["index_document"]], [])

    content {
      suffix = index_document.value
    }
  }

  dynamic "error_document" {
    for_each = try([var.website["error_document"]], [])

    content {
      key = error_document.value
    }
  }

  dynamic "redirect_all_requests_to" {
    for_each = try([var.website["redirect_all_requests_to"]], [])

    content {
      host_name = redirect_all_requests_to.value.host_name
      protocol  = try(redirect_all_requests_to.value.protocol, null)
    }
  }

  dynamic "routing_rule" {
    for_each = try(flatten([var.website["routing_rules"]]), [])

    content {
      dynamic "condition" {
        for_each = try([routing_rule.value.condition], [])

        content {
          http_error_code_returned_equals = try(routing_rule.value.condition["http_error_code_returned_equals"], null)
          key_prefix_equals               = try(routing_rule.value.condition["key_prefix_equals"], null)
        }
      }

      redirect {
        host_name               = try(routing_rule.value.redirect["host_name"], null)
        http_redirect_code      = try(routing_rule.value.redirect["http_redirect_code"], null)
        protocol                = try(routing_rule.value.redirect["protocol"], null)
        replace_key_prefix_with = try(routing_rule.value.redirect["replace_key_prefix_with"], null)
        replace_key_with        = try(routing_rule.value.redirect["replace_key_with"], null)
      }
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  count = local.create_bucket && length(keys(var.versioning)) > 0 ? 1 : 0

  bucket                = aws_s3_bucket.this[0].id
  expected_bucket_owner = var.expected_bucket_owner
  mfa                   = try(var.versioning["mfa"], null)

  versioning_configuration {
    # Valid values: "Enabled" or "Suspended"
    status = try(var.versioning["enabled"] ? "Enabled" : "Suspended", tobool(var.versioning["status"]) ? "Enabled" : "Suspended", title(lower(var.versioning["status"])), "Enabled")

    # Valid values: "Enabled" or "Disabled"
    mfa_delete = try(tobool(var.versioning["mfa_delete"]) ? "Enabled" : "Disabled", title(lower(var.versioning["mfa_delete"])), null)
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted_bucket" {
  bucket = aws_s3_bucket.this[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = local.kms_master_key_id
      sse_algorithm     = local.sse_algorithm
    }
    bucket_key_enabled = local.enable_bucket_key
  }
}


resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count = local.create_bucket && length(keys(var.server_side_encryption_configuration)) > 0 ? 1 : 0

  bucket                = aws_s3_bucket.this[0].id
  expected_bucket_owner = var.expected_bucket_owner

  dynamic "rule" {
    for_each = try(flatten([var.server_side_encryption_configuration["rule"]]), [])

    content {
      bucket_key_enabled = try(rule.value.bucket_key_enabled, null)

      dynamic "apply_server_side_encryption_by_default" {
        for_each = try([rule.value.apply_server_side_encryption_by_default], [])

        content {
          sse_algorithm     = apply_server_side_encryption_by_default.value.sse_algorithm
          kms_master_key_id = try(apply_server_side_encryption_by_default.value.kms_master_key_id, null)
        }
      }
    }
  }
}

resource "aws_s3_bucket_cors_configuration" "this" {
  count = local.create_bucket && length(local.cors_rules) > 0 ? 1 : 0

  bucket                = aws_s3_bucket.this[0].id
  expected_bucket_owner = var.expected_bucket_owner

  dynamic "cors_rule" {
    for_each = local.cors_rules

    content {
      id              = try(cors_rule.value.id, null)
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      allowed_headers = try(cors_rule.value.allowed_headers, null)
      expose_headers  = try(cors_rule.value.expose_headers, null)
      max_age_seconds = try(cors_rule.value.max_age_seconds, null)
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count = local.create_bucket && length(local.lifecycle_rules) > 0 ? 1 : 0

  bucket                = aws_s3_bucket.this[0].id
  expected_bucket_owner = var.expected_bucket_owner
  # transition_default_minimum_object_size = var.transition_default_minimum_object_size

  dynamic "rule" {
    for_each = local.lifecycle_rules

    content {
      id     = try(rule.value.id, null)
      status = try(rule.value.enabled ? "Enabled" : "Disabled", tobool(rule.value.status) ? "Enabled" : "Disabled", title(lower(rule.value.status)))

      # Max 1 block - abort_incomplete_multipart_upload
      dynamic "abort_incomplete_multipart_upload" {
        for_each = try([rule.value.abort_incomplete_multipart_upload_days], [])

        content {
          days_after_initiation = try(rule.value.abort_incomplete_multipart_upload_days, null)
        }
      }


      # Max 1 block - expiration
      dynamic "expiration" {
        for_each = try(flatten([rule.value.expiration]), [])

        content {
          date                         = try(expiration.value.date, null)
          days                         = try(expiration.value.days, null)
          expired_object_delete_marker = try(expiration.value.expired_object_delete_marker, null)
        }
      }

      # Several blocks - transition
      dynamic "transition" {
        for_each = try(flatten([rule.value.transition]), [])

        content {
          date          = try(transition.value.date, null)
          days          = try(transition.value.days, null)
          storage_class = transition.value.storage_class
        }
      }

      # Max 1 block - noncurrent_version_expiration
      dynamic "noncurrent_version_expiration" {
        for_each = try(flatten([rule.value.noncurrent_version_expiration]), [])

        content {
          newer_noncurrent_versions = try(noncurrent_version_expiration.value.newer_noncurrent_versions, null)
          noncurrent_days           = try(noncurrent_version_expiration.value.days, noncurrent_version_expiration.value.noncurrent_days, null)
        }
      }

      # Several blocks - noncurrent_version_transition
      dynamic "noncurrent_version_transition" {
        for_each = try(flatten([rule.value.noncurrent_version_transition]), [])

        content {
          newer_noncurrent_versions = try(noncurrent_version_transition.value.newer_noncurrent_versions, null)
          noncurrent_days           = try(noncurrent_version_transition.value.days, noncurrent_version_transition.value.noncurrent_days, null)
          storage_class             = noncurrent_version_transition.value.storage_class
        }
      }

      # Max 1 block - filter - without any key arguments or tags
      dynamic "filter" {
        for_each = length(try(flatten([rule.value.filter]), [])) == 0 ? [true] : []

        content {
          #          prefix = ""
        }
      }

      # Max 1 block - filter - with one key argument or a single tag
      dynamic "filter" {
        for_each = [for v in try(flatten([rule.value.filter]), []) : v if max(length(keys(v)), length(try(rule.value.filter.tags, rule.value.filter.tag, []))) == 1]

        content {
          object_size_greater_than = try(filter.value.object_size_greater_than, null)
          object_size_less_than    = try(filter.value.object_size_less_than, null)
          prefix                   = try(filter.value.prefix, null)

          dynamic "tag" {
            for_each = try(filter.value.tags, filter.value.tag, [])

            content {
              key   = tag.key
              value = tag.value
            }
          }
        }
      }

      # Max 1 block - filter - with more than one key arguments or multiple tags
      dynamic "filter" {
        for_each = [for v in try(flatten([rule.value.filter]), []) : v if max(length(keys(v)), length(try(rule.value.filter.tags, rule.value.filter.tag, []))) > 1]

        content {
          and {
            object_size_greater_than = try(filter.value.object_size_greater_than, null)
            object_size_less_than    = try(filter.value.object_size_less_than, null)
            prefix                   = try(filter.value.prefix, null)
            tags                     = try(filter.value.tags, filter.value.tag, null)
          }
        }
      }
    }
  }

  # Must have bucket versioning enabled first
  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  count = local.create_bucket && var.object_lock_enabled && try(var.object_lock_configuration.rule.default_retention, null) != null ? 1 : 0

  bucket                = aws_s3_bucket.this[0].id
  expected_bucket_owner = var.expected_bucket_owner
  token                 = try(var.object_lock_configuration.token, null)

  rule {
    default_retention {
      mode  = var.object_lock_configuration.rule.default_retention.mode
      days  = try(var.object_lock_configuration.rule.default_retention.days, null)
      years = try(var.object_lock_configuration.rule.default_retention.years, null)
    }
  }
}


resource "aws_s3_bucket_policy" "this" {
  count = local.create_bucket && local.attach_policy ? 1 : 0

  bucket = aws_s3_bucket.this[0].id
  # policy = data.aws_iam_policy_document.combined[0].json

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::${aws_s3_bucket.this[0].bucket}/*"
      }
    ]
  })

  depends_on = [
    aws_s3_bucket_public_access_block.this
  ]
}

data "aws_iam_policy_document" "combined" {
  count = local.create_bucket && local.attach_policy ? 1 : 0

  source_policy_documents = compact([
    var.attach_elb_log_delivery_policy ? data.aws_iam_policy_document.elb_log_delivery[0].json : "",
    var.attach_lb_log_delivery_policy ? data.aws_iam_policy_document.lb_log_delivery[0].json : "",
    var.attach_access_log_delivery_policy ? data.aws_iam_policy_document.access_log_delivery[0].json : "",
    var.attach_require_latest_tls_policy ? data.aws_iam_policy_document.require_latest_tls[0].json : "",
    var.attach_deny_insecure_transport_policy ? data.aws_iam_policy_document.deny_insecure_transport[0].json : "",
    var.attach_deny_unencrypted_object_uploads ? data.aws_iam_policy_document.deny_unencrypted_object_uploads[0].json : "",
    var.attach_policy ? var.policy : ""
  ])
}

# AWS Load Balancer access log delivery policy
locals {
  # List of AWS regions where permissions should be granted to the specified Elastic Load Balancing account ID ( https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy )
  elb_service_accounts = {
    us-east-1      = "127311923021"
    us-east-2      = "033677994240"
    us-west-1      = "027434742980"
    us-west-2      = "797873946194"
    af-south-1     = "098369216593"
    ap-east-1      = "754344448648"
    ap-south-1     = "718504428378"
    ap-northeast-1 = "582318560864"
    ap-northeast-2 = "600734575887"
    ap-northeast-3 = "383597477331"
    ap-southeast-1 = "114774131450"
    ap-southeast-2 = "783225319266"
    ap-southeast-3 = "589379963580"
    ca-central-1   = "985666609251"
    eu-central-1   = "054676820928"
    eu-west-1      = "156460612806"
    eu-west-2      = "652711504416"
    eu-west-3      = "009996457667"
    eu-south-1     = "635631232127"
    eu-north-1     = "897822967062"
    me-south-1     = "076674570225"
    sa-east-1      = "507241528517"
    us-gov-west-1  = "048591011584"
    us-gov-east-1  = "190560391635"
    cn-north-1     = "638102146993"
    cn-northwest-1 = "037604701340"
  }
}

data "aws_iam_policy_document" "elb_log_delivery" {
  count = local.create_bucket && var.attach_elb_log_delivery_policy ? 1 : 0

  # Policy for AWS Regions created before August 2022 (e.g. US East (N. Virginia), Asia Pacific (Singapore), Asia Pacific (Sydney), Asia Pacific (Tokyo), Europe (Ireland))
  dynamic "statement" {
    for_each = { for k, v in local.elb_service_accounts : k => v if k == data.aws_region.current.name }

    content {
      sid = format("ELBRegion%s", title(statement.key))

      principals {
        type        = "AWS"
        identifiers = [format("arn:%s:iam::%s:root", data.aws_partition.current.partition, statement.value)]
      }

      effect = "Allow"

      actions = [
        "s3:PutObject",
      ]

      resources = [
        "${aws_s3_bucket.this[0].arn}/*",
      ]
    }
  }

  # Policy for AWS Regions created after August 2022 (e.g. Asia Pacific (Hyderabad), Asia Pacific (Melbourne), Europe (Spain), Europe (Zurich), Middle East (UAE))
  statement {
    sid = ""

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*",
    ]
  }
}

# ALB/NLB
data "aws_iam_policy_document" "lb_log_delivery" {
  count = local.create_bucket && var.attach_lb_log_delivery_policy ? 1 : 0

  statement {
    sid = "AWSLogDeliveryWrite"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid = "AWSLogDeliveryAclCheck"

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
      "s3:ListBucket",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
    ]

  }
}

# Grant access to S3 log delivery group for server access logging

data "aws_iam_policy_document" "access_log_delivery" {
  count = local.create_bucket && var.attach_access_log_delivery_policy ? 1 : 0

  statement {
    sid = "AWSAccessLogDeliveryWrite"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    dynamic "condition" {
      for_each = length(var.access_log_delivery_policy_source_buckets) != 0 ? [true] : []
      content {
        test     = "ForAnyValue:ArnLike"
        variable = "aws:SourceArn"
        values   = var.access_log_delivery_policy_source_buckets
      }
    }

    dynamic "condition" {
      for_each = length(var.access_log_delivery_policy_source_accounts) != 0 ? [true] : []
      content {
        test     = "ForAnyValue:StringEquals"
        variable = "aws:SourceAccount"
        values   = var.access_log_delivery_policy_source_accounts
      }
    }

  }

  statement {
    sid = "AWSAccessLogDeliveryAclCheck"

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
    ]

  }
}

data "aws_iam_policy_document" "deny_insecure_transport" {
  count = local.create_bucket && var.attach_deny_insecure_transport_policy ? 1 : 0

  statement {
    sid    = "denyInsecureTransport"
    effect = "Deny"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values = [
        "false"
      ]
    }
  }
}

data "aws_iam_policy_document" "require_latest_tls" {
  count = local.create_bucket && var.attach_require_latest_tls_policy ? 1 : 0

  statement {
    sid    = "denyOutdatedTLS"
    effect = "Deny"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values = [
        "1.2"
      ]
    }
  }
}

data "aws_iam_policy_document" "deny_unencrypted_object_uploads" {
  count = local.create_bucket && var.attach_deny_unencrypted_object_uploads ? 1 : 0

  statement {
    sid    = "denyUnencryptedObjectUploads"
    effect = "Deny"

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*"
    ]

    principals {
      identifiers = ["*"]
      type        = "*"
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = [true]
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  count = local.create_bucket && var.attach_public_policy ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  block_public_acls       = var.block_public_acls
  block_public_policy     = var.block_public_policy
  ignore_public_acls      = var.ignore_public_acls
  restrict_public_buckets = var.restrict_public_buckets
}

resource "aws_s3_bucket_ownership_controls" "this" {
  count = local.create_bucket && var.control_object_ownership ? 1 : 0

  bucket = local.attach_policy ? aws_s3_bucket_policy.this[0].id : aws_s3_bucket.this[0].id

  rule {
    object_ownership = var.object_ownership
  }

  # This `depends_on` is to prevent "A conflicting conditional operation is currently in progress against this resource."
  depends_on = [
    aws_s3_bucket_policy.this,
    aws_s3_bucket_public_access_block.this,
    aws_s3_bucket.this
  ]
}

