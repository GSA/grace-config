# <a name="top">GRACE Config</a> [![CircleCI](https://circleci.com/gh/GSA/grace-config.svg?style=shield)](https://circleci.com/gh/GSA/grace-config)

GRACE Config sets up AWS Config and provides some baseline AWS Config rules that assist with the monitoring of an AWS environment.

## Table of Contents

- [Security Compliance](#security-compliance)
- [Repository contents](#repository-contents)
- [Usage](#usage)
- [Terraform Module Inputs](#terraform-module-inputs)
- [Terraform Module Outputs](#terraform-module-outputs)

## Security Compliance

**Component ATO status:** draft

**Relevant controls:**

| Control    | CSP/AWS | HOST/OS | App/DB | How is it implemented? |
| ---------- | ------- | ------- | ------ | ---------------------- |


[top](#top)

## Repository contents

- **config.tf** contains the setup and configuration for AWS Config
- **rules.tf** contains all of the declarations for AWS Config rules
- **variables.tf** contains all configurable variables
- **outputs.tf** contains all Terraform output variables

[top](#top)

# Usage

Simply import grace-config as a module into your Terraform for the destination AWS Environment.

```
module "config" {
    source = "github.com/GSA/grace-config?ref=v0.0.1"
    bucket = "<bucket_name>"
}
```

[top](#top)

## Terraform Module Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| bucket | The S3 bucket where AWS Config files will be stored | string |  | yes |
| bucket_prefix | The Key prefix used for AWS Config file storage | string | awsconfig | no |
| access_logging_bucket | if provided, this is used during the s3_bucket_logging_enabled_check | string | | no
| enable_config | The boolean value indicating whether AWS Config should be enabled | bool | true | no |
| config_record_all_supported_types | Specifies whether AWS Config records configuration changes for every supported type of regional resource (which includes any new type that will become supported in the future) | bool | true | no |
| config_record_global_resource_types | Specifies whether AWS Config includes all supported types of global resources with the resources that it records | bool | true | no |
| config_snapshot_frequency | The interval in which AWS Config creates snapshots of the environment (One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours) | string | Three_Hours | no |
| enable_cloudwatch_alarm_action_check | The boolean value indicating whether to check that all cloudwatch alarms have at least one action | bool | true | no |
| enable_cloudtrail_enabled_check | The boolean value indicating whether to check that CloudTrail is enabled | bool | true | no |
| enable_iam_password_policy_check | The boolean value indicating whether to check that the account password policy for IAM users meets the specified requirements | bool | true | no |
| iam_password_policy_require_uppercase | The boolean value indicating whether the password policy requires uppercase letters | bool | true | no |
| iam_password_policy_require_lowercase | The boolean value indicating whether the password policy requires lowercase letters | bool | true | no |
| iam_password_policy_require_symbols | The boolean value indicating whether the password policy requires symbols | bool | true | no |
| iam_password_policy_require_numbers | The boolean value indicating whether the password policy requires numbers | bool | true | no |
| iam_password_policy_min_length | The boolean value indicating the minimum password length | number | 16 | no |
| iam_password_policy_history_length | The boolean value indicating the number of passwords to remember and prevent reuse | number | 10 | no |
| enable_cloudtrail_encryption_enabled_check | The boolean value indicating whether to check that CloudTrail is using server-side encryption | bool | true | no |
| enable_mfa_enabled_for_iam_users_check | The boolean value indicating whether to check that all IAM Users (console-only) are configured for multi-factor authentication | bool | true | no |
| enable_iam_inactive_credentials_check | The boolean value indicating whether to check for stale passwords or access keys for all IAM users | bool | true | no |
| iam_inactive_credentials_days | The number of days before a credential should be considered inactive | number | 90 | no |
| enable_root_account_mfa_enabled_check | The boolean value indicating whether AWS Config should be enabled | bool | true | no |
| enable_config | The boolean value indicating whether to check that the root account is configured with multi-factor authentication | bool | true | no |
| enable_access_key_expiration_check | The boolean value indicating whether to check for expired access keys (see access_key_expiration_days) | bool | true | no |
| access_key_expiration_days | The number of days before an access key is considered expired | number | 90 | no |
| enable_cloudtrail_logfile_validation_check | The boolean value indicating whether to check that CloudTrail is using a signed digest file | bool | true | no |
| enable_cloudtrail_cloudwatch_logs_enabled_check | The boolean value indicating whether to check that CloudTrail is logging to CloudWatch Logs | bool | true | no |
| enable_s3_bucket_logging_enabled_check | The boolean value indicating whether to check that S3 buckets having access logging enabled | bool | true | no |
| enable_iam_root_access_key_check | The boolean value indicating whether to check if the root user has an access key available | bool | true | no |
| enable_s3_bucket_public_read_prohibited_check | The boolean value indicating whether to check S3 buckets for public read access | bool | true | no |
| enable_s3_bucket_public_write_prohibited_check | The boolean value indicating whether to check S3 buckets for public write access | bool | true | no |
| enable_s3_bucket_sse_enabled_check | The boolean value indicating whether to check S3 buckets for server-side encryption | bool | true | no |
| enable_s3_bucket_versioning_enabled_check | The boolean value indicating whether to check S3 buckets for versioning enabled | bool | true | no |
| enable_guardduty_enabled_check | The boolean value indicating whether to check if GuardDuty is enabled | bool | true | no |

[top](#top)

## Terraform Module Outputs

| Name | Description |
|------|-------------|
| config_service_role_arn | The Amazon Resource Name (ARN) identifying the AWS Config service IAM Role |

[top](#top)

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

[top](#top)