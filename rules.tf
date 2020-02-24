#######################
# AWS Config Rules    #
#######################

resource "aws_config_config_rule" "cloudwatch_alarm_action_check" {
  count       = var.enable_cloudwatch_alarm_action_check ? 1 : 0
  name        = "cloudwatch-alarm-action-check"
  description = "Checks whether CloudWatch alarms have at least one alarm action, one INSUFFICIENT_DATA action, or one OK action enabled. Optionally, checks whether any of the actions matches one of the specified ARNs."

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_ACTION_CHECK"
  }

  input_parameters = <<EOF
{
  "alarmActionRequired" : "true",
  "insufficientDataActionRequired" : "false",
  "okActionRequired" : "false"
}
EOF

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "cloudtrail_enabled_check" {
  count       = var.enable_cloudtrail_enabled_check ? 1 : 0
  name        = "cloudtrail-enabled-check"
  description = "Checks whether AWS CloudTrail is enabled in your AWS account. Optionally, you can specify which S3 bucket, SNS topic, and Amazon CloudWatch Logs ARN to use."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "iam_password_policy_check" {
  count       = var.enable_iam_password_policy_check ? 1 : 0
  name        = "iam-password-policy-check"
  description = "Checks whether the account password policy for IAM users meets the specified requirements."

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = <<EOF
{
  "RequireUppercaseCharacters" : "${var.iam_password_policy_require_uppercase}",
  "RequireLowercaseCharacters" : "${var.iam_password_policy_require_lowercase}",
  "RequireSymbols" : "${var.iam_password_policy_require_symbols}",
  "RequireNumbers" : "${var.iam_password_policy_require_numbers}",
  "MinimumPasswordLength" : "${var.iam_password_policy_min_length}",
  "PasswordReusePrevention" : "${var.iam_password_policy_history_length}",
  "MaxPasswordAge" : "${var.iam_password_policy_max_age_days}"
}
EOF

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "cloudtrail_encryption_enabled_check" {
  count       = var.enable_cloudtrail_encryption_enabled_check ? 1 : 0
  name        = "cloud-trail-encryption-enabled-check"
  description = "Checks whether AWS CloudTrail is configured to use the server side encryption (SSE) AWS Key Management Service (AWS KMS) customer master key (CMK) encryption. The rule is COMPLIANT if the KmsKeyId is defined."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "mfa_enabled_for_iam_users_check" {
  count       = var.enable_mfa_enabled_for_iam_users_check ? 1 : 0
  name        = "mfa-enabled-for-iam-users-check"
  description = "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password."

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "iam_inactive_credentials_check" {
  count       = var.enable_iam_inactive_credentials_check ? 1 : 0
  name        = "iam-inactive-credentials-check"
  description = "Checks whether your AWS Identity and Access Management (IAM) users have passwords or active access keys that have not been used within the specified number of days you provided."

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }

  input_parameters = <<EOF
{
  "maxCredentialUsageAge" : "${var.iam_inactive_credentials_days}"
}
EOF

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "root_account_mfa_enabled_check" {
  count       = var.enable_root_account_mfa_enabled_check ? 1 : 0
  name        = "root-account-mfa-enabled-check"
  description = "Checks whether users of your AWS account require a multi-factor authentication MFA device to sign in with root credentials.."

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "access_key_expiration_check" {
  count       = var.enable_access_key_expiration_check ? 1 : 0
  name        = "access-key-expiration-check"
  description = "Checks whether the active access keys are rotated within the number of days specified in maxAccessKeyAge. The rule is non-compliant if the access keys have not been rotated for more than maxAccessKeyAge number of days."

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = <<EOF
{
  "maxAccessKeyAge" : "${var.access_key_expiration_days}"
}
EOF

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "cloudtrail_logfile_validation_check" {
  count       = var.enable_cloudtrail_logfile_validation_check ? 1 : 0
  name        = "cloudtrail-log-file-validation-check"
  description = "Checks whether AWS CloudTrail creates a signed digest file with logs. The rule is NON_COMPLIANT if the validation is not enabled."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "cloudtrail_cloudwatch_logs_enabled_check" {
  count       = var.enable_cloudtrail_cloudwatch_logs_enabled_check ? 1 : 0
  name        = "cloudtrail-cloudwatch-logs-enabled-check"
  description = "Checks whether AWS CloudTrail trails are configured to send logs to Amazon CloudWatch Logs. The trail is NON_COMPLIANT if the CloudWatchLogsLogGroupArn property of the trail is empty."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "s3_bucket_logging_enabled_check" {
  count       = var.enable_s3_bucket_logging_enabled_check && length(var.access_logging_bucket) > 0 ? 1 : 0
  name        = "s3-bucket-logging-enabled-check"
  description = "Checks whether logging is enabled for your S3 buckets."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LOGGING_ENABLED"
  }

  input_parameters = <<EOF
{
  "targetBucket": "${var.access_logging_bucket}"
}
EOF

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "iam_root_access_key_check" {
  count       = var.enable_iam_root_access_key_check ? 1 : 0
  name        = "iam-root-access-key-check"
  description = "Checks whether the root user access key is available. The rule is compliant if the user access key does not exist."

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "s3_bucket_public_read_prohibited_check" {
  count       = var.enable_s3_bucket_public_read_prohibited_check ? 1 : 0
  name        = "s3-bucket-public-read-prohibited-check"
  description = "Checks that your Amazon S3 buckets do not allow public read access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL)."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "s3_bucket_public_write_prohibited_check" {
  count       = var.enable_s3_bucket_public_write_prohibited_check ? 1 : 0
  name        = "s3-bucket-public-write-prohibited-check"
  description = "Checks that your Amazon S3 buckets do not allow public write access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL)."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "s3_bucket_sse_enabled_check" {
  count       = var.enable_s3_bucket_sse_enabled_check ? 1 : 0
  name        = "s3-bucket-server-side-encryption-enabled-check"
  description = "Checks that your Amazon S3 bucket either has Amazon S3 default encryption enabled or that the S3 bucket policy explicitly denies put-object requests without server side encryption."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "s3_bucket_versioning_enabled_check" {
  count       = var.enable_s3_bucket_versioning_enabled_check ? 1 : 0
  name        = "s3-bucket-versioning-enabled-check"
  description = "Checks whether versioning is enabled for your S3 buckets. Optionally, the rule checks if MFA delete is enabled for your S3 buckets."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_config_rule" "guardduty_enabled_check" {
  count       = var.enable_guardduty_enabled_check ? 1 : 0
  name        = "guardduty-enabled-check"
  description = "Checks whether Amazon GuardDuty is enabled in your AWS account and region."

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [aws_config_configuration_recorder.config]
}
