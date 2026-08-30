resource "aws_s3_bucket" "training_data" {
  bucket = "acme-training-data"
}
resource "aws_s3_bucket_acl" "training_data" {
  bucket = aws_s3_bucket.training_data.id
  acl    = "public-read"
}
resource "aws_s3_bucket" "model_weights" {
  bucket = "acme-model-weights"
}
resource "aws_s3_bucket" "datasets" {
  bucket = "acme-public-datasets"
}
resource "aws_s3_bucket_policy" "datasets" {
  bucket = aws_s3_bucket.datasets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = ["arn:aws:s3:::acme-public-datasets/*"]
    }]
  })
}

# Carries all three non-hygiene S3-001 defects at once: public ACL, a
# wildcard-principal policy, and a weakened (not fully blocked) public
# access block. Regression fixture for MM-03 - these three findings must
# not collapse onto one fingerprint.
resource "aws_s3_bucket" "multi_defect" {
  bucket = "acme-multi-defect-ai-training"
}
resource "aws_s3_bucket_acl" "multi_defect" {
  bucket = aws_s3_bucket.multi_defect.id
  acl    = "public-read"
}
resource "aws_s3_bucket_policy" "multi_defect" {
  bucket = aws_s3_bucket.multi_defect.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = ["arn:aws:s3:::acme-multi-defect-ai-training/*"]
    }]
  })
}
resource "aws_s3_bucket_public_access_block" "multi_defect" {
  bucket                  = aws_s3_bucket.multi_defect.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
