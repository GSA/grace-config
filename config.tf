#######################
# AWS Config Setup    #
#######################

resource "aws_config_configuration_recorder" "config" {
  name     = "config-service"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = var.config_record_all_supported_types
    include_global_resource_types = var.config_record_global_resource_types
  }
}

resource "aws_config_delivery_channel" "config" {
  name           = "config-service"
  s3_bucket_name = var.bucket
  s3_key_prefix  = var.bucket_prefix

  snapshot_delivery_properties {
    delivery_frequency = var.config_snapshot_frequency
  }

  depends_on = [aws_config_configuration_recorder.config]
}

resource "aws_config_configuration_recorder_status" "config" {
  name       = aws_config_configuration_recorder.config.name
  is_enabled = var.enable_config

  depends_on = [aws_config_delivery_channel.config]
}

resource "aws_iam_role" "config" {
  name = "config-service"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}
