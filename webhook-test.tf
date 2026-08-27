# Temporary file for testing the modelmoat-bot GitHub App end to end.
# Deliberately insecure - safe to merge or delete once the PR comment is verified.
resource "aws_s3_bucket" "webhook_test_datasets" {
  bucket = "webhook-test-datasets"
}
resource "aws_s3_bucket_policy" "webhook_test_datasets" {
  bucket = aws_s3_bucket.webhook_test_datasets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = ["arn:aws:s3:::webhook-test-datasets/*"]
    }]
  })
}
