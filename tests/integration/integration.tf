resource "aws_s3_bucket" "bucket" {
  bucket = "bucket"
}

module "integration_test" {
  source = "../../"
  bucket = aws_s3_bucket.bucket.bucket
}
