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
