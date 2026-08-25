resource "aws_s3_bucket" "model_artifacts" {
  bucket = "acme-prod-model-artifacts"
  tags = {
    Team = "ml-platform"
  }
}
