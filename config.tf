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
  depends_on = [var.module_depends_on]
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
