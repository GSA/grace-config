output "config_service_role_arn" {
  value       = aws_iam_role.config.arn
  description = "The Amazon Resource Name (ARN) identifying the AWS Config service IAM Role"
}
