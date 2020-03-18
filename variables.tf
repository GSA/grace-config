variable "bucket" {
  type        = string
  description = "(required) The S3 bucket where AWS Config files will be stored"
}

variable "module_depends_on" {
  type    = any
  default = null
}

variable "bucket_prefix" {
  type        = string
  description = "(optional) The Key prefix used for AWS Config file storage"
  default     = "awsconfig"
}

variable "access_logging_bucket" {
  type        = string
  description = "(optional) if provided, this is used during the s3_bucket_logging_enabled_check"
  default     = ""
}

variable "enable_config" {
  type        = bool
  description = "(optional) The boolean value indicating whether AWS Config should be enabled"
  default     = true
}

variable "config_record_all_supported_types" {
  type        = bool
  description = "(optional) Specifies whether AWS Config records configuration changes for every supported type of regional resource (which includes any new type that will become supported in the future)"
  default     = true
}

variable "config_record_global_resource_types" {
  type        = bool
  description = "(optional) Specifies whether AWS Config includes all supported types of global resources with the resources that it records"
  default     = true
}

variable "config_snapshot_frequency" {
  type        = string
  description = "(optional) The interval in which AWS Config creates snapshots of the environment (One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours)"
  default     = "Three_Hours"
}

variable "enable_cloudwatch_alarm_action_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that all cloudwatch alarms have at least one action"
  default     = true
}

variable "enable_cloudtrail_enabled_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that CloudTrail is enabled"
  default     = true
}

variable "enable_iam_password_policy_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that the account password policy for IAM users meets the specified requirements"
  default     = true
}

variable "iam_password_policy_require_uppercase" {
  type        = bool
  description = "(optional) The boolean value indicating whether the password policy requires uppercase letters"
  default     = true
}

variable "iam_password_policy_require_lowercase" {
  type        = bool
  description = "(optional) The boolean value indicating whether the password policy requires lowercase letters"
  default     = true
}

variable "iam_password_policy_require_symbols" {
  type        = bool
  description = "(optional) The boolean value indicating whether the password policy requires symbols"
  default     = true
}

variable "iam_password_policy_require_numbers" {
  type        = bool
  description = "(optional) The boolean value indicating whether the password policy requires numbers"
  default     = true
}

variable "iam_password_policy_min_length" {
  type        = number
  description = "(optional) The boolean value indicating the minimum password length"
  default     = 16
}

variable "iam_password_policy_history_length" {
  type        = number
  description = "(optional) The boolean value indicating the number of passwords to remember and prevent reuse"
  default     = 10
}

variable "iam_password_policy_max_age_days" {
  type        = number
  description = "(optional) The boolean value indicating the number of days before a password expires"
  default     = 90
}

variable "enable_cloudtrail_encryption_enabled_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that CloudTrail is using server-side encryption"
  default     = true
}

variable "enable_mfa_enabled_for_iam_users_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that all IAM Users (console-only) are configured for multi-factor authentication"
  default     = true
}

variable "enable_iam_inactive_credentials_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check for stale passwords or access keys for all IAM users"
  default     = true
}

variable "iam_inactive_credentials_days" {
  type        = number
  description = "(optional) The number of days before a credential should be considered inactive"
  default     = 90
}

variable "enable_root_account_mfa_enabled_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that the root account is configured with multi-factor authentication"
  default     = true
}

variable "enable_access_key_expiration_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check for expired access keys (see access_key_expiration_days)"
  default     = true
}

variable "access_key_expiration_days" {
  type        = number
  description = "(optional) The number of days before an access key is considered expired"
  default     = 90
}

variable "enable_cloudtrail_logfile_validation_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that CloudTrail is using a signed digest file"
  default     = true
}

variable "enable_cloudtrail_cloudwatch_logs_enabled_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that CloudTrail is logging to CloudWatch Logs"
  default     = true
}

variable "enable_s3_bucket_logging_enabled_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check that S3 buckets having access logging enabled"
  default     = true
}

variable "enable_iam_root_access_key_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check if the root user has an access key available"
  default     = true
}

variable "enable_s3_bucket_public_read_prohibited_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check S3 buckets for public read access"
  default     = true
}

variable "enable_s3_bucket_public_write_prohibited_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check S3 buckets for public write access"
  default     = true
}

variable "enable_s3_bucket_sse_enabled_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check S3 buckets for server-side encryption"
  default     = true
}

variable "enable_s3_bucket_versioning_enabled_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check S3 buckets for versioning enabled"
  default     = true
}

variable "enable_guardduty_enabled_check" {
  type        = bool
  description = "(optional) The boolean value indicating whether to check if GuardDuty is enabled"
  default     = true
}
