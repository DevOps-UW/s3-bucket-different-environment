variable "bucket_name" {
  description = "The name of the S3 bucket."
  type        = string
}
variable "tags" {
  description = "A map of tags to assign to the S3 bucket."
  type        = map(string)
}

variable "attach_policy" {
  description = "Whether to attach a policy to the S3 bucket."
  type        = bool
}

variable "policy" {
  description = "The policy document to attach to the S3 bucket."
  type        = string
}

variable "attach_deny_insecure_transport_policy" {
  description = "Whether to attach a policy that denies insecure transport."
  type        = bool
}

variable "attach_require_latest_tls_policy" {
  description = "Whether to attach a policy that requires the latest TLS version."
  type        = bool
}

variable "allowed_kms_key_arn" {
  description = "The ARN of the KMS key allowed for encryption."
  type        = string
}

variable "attach_deny_unencrypted_object_uploads" {
  description = "Whether to attach a policy that denies unencrypted object uploads."
  type        = bool
}

variable "control_object_ownership" {
  description = "Whether to control object ownership."
  type        = bool
}

variable "object_ownership" {
  description = "The object ownership setting for the S3 bucket."
  type        = string
}

variable "transition_default_minimum_object_size" {
  description = "The minimum object size for transition."
  type        = number
}

variable "acl" {
  description = "The ACL for the S3 bucket."
  type        = string
}

variable "versioning" {
  description = "Whether to enable versioning on the S3 bucket."
  type        = bool
}

variable "website" {
  description = "The website configuration for the S3 bucket."
  type        = any
}

variable "kms_key_arn" {
  description = "The ARN of the KMS key for server-side encryption."
  type        = string
}

variable "cors_rule" {
  description = "The CORS configuration for the S3 bucket."
  type        = any
}

variable "lifecycle_rule" {
  description = "The lifecycle rules for the S3 bucket."
  type        = any
}

variable "intelligent_tiering" {
  description = "Whether to enable intelligent tiering for the S3 bucket."
  type        = bool
}

variable "metric_configuration" {
  description = "The metric configuration for the S3 bucket."
  type        = any
}

variable "log_bucket_name" {
  description = "The name of the bucket for logging."
  type        = string
}

variable "days" {
  description = "The number of days for object lock retention."
  type        = number
}