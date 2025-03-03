variable "region" {
  description = "The AWS region to deploy resources in"
  type        = string
}

variable "bucket_name" {
  description = "buctet name "
  type = string
}

variable "tags" {
  description = "(Optional) A mapping of tags to assign to the bucket."
  type        = map(string)
  default     = {}
}
variable "days" {
  description = "Number of days for the lifecycle rule"
  type        = number
  default     = 1
}

variable "attach_policy" {
  description = "Whether to attach the bucket policy"
  type        = bool
  default     = true
}

variable "attach_deny_insecure_transport_policy" {
  description = "Whether to attach the deny insecure transport policy"
  type        = bool
  default     = false
}

variable "attach_require_latest_tls_policy" {
  description = "Whether to attach the require latest TLS policy"
  type        = bool
  default     = false
}

variable "attach_deny_incorrect_encryption_headers" {
  description = "Whether to attach the deny incorrect encryption headers policy"
  type        = bool
  default     = false
}

variable "attach_deny_incorrect_kms_key_sse" {
  description = "Whether to attach the deny incorrect KMS key SSE policy"
  type        = bool
  default     = false
}

variable "allowed_kms_key_arn" {
  description = "ARN of the allowed KMS key"
  type        = string
  default     = ""
}

variable "attach_deny_unencrypted_object_uploads" {
  description = "Whether to attach the deny unencrypted object uploads policy"
  type        = bool
  default     = true
}

variable "block_public_acls" {
  description = "Whether to block public ACLs"
  type        = bool
  default     = true
}

variable "block_public_policy" {
  description = "Whether to block public policies"
  type        = bool
  default     = true
}

variable "control_object_ownership" {
  type = any
}

variable "object_ownership" {
  type = any
}
variable "transition_default_minimum_object_size" {
  type = any
}

variable "acl" {
  type = any
}

variable "versioning" {
  type = any
}

variable "website" {
  type = any
}

variable "cors_rule" {
  type = any
}
  
variable "lifecycle_rule" {
  type = any
}

variable "intelligent_tiering" {
  type = any
}
variable "metric_configuration" {
  type = any
}

variable "kms_key_arn" {
  description = "KMS Key ARN for encryption. Leave empty to use the AWS default key. To use a custom key, set the ARN here."
  type        = string
  default     = ""
}

variable "log_bucket_name" {
  description = "S3 bucket to store access logs"
  type        = string
}

# variable "server_side_encryption_configuration" {
#   description = "Server-side encryption configuration for the S3 bucket"
#   type = object({
#     rule = list(object({
#       bucket_key_enabled = optional(bool, true)
#       apply_server_side_encryption_by_default = object({
#         sse_algorithm     = string
#         kms_master_key_id = optional(string, null)
#       })
#     }))
#   })
#   default = {
#     rule = [{
#       bucket_key_enabled = true
#       apply_server_side_encryption_by_default = {
#         sse_algorithm     = "AES256"  # Default to S3-managed encryption
#         kms_master_key_id = null      # No custom KMS key by default
#       }
#     }]
#   }
# }

