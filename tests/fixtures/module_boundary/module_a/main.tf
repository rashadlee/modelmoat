resource "aws_s3_bucket" "data" {
  bucket = "acme-module-a-training-data"
}
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
