resource "aws_bedrockagent_knowledge_base" "acme_support" {
  name     = "acme-support-kb"
  role_arn = "arn:aws:iam::123456789012:role/acme-kb-role"
  knowledge_base_configuration {
    type = "VECTOR"
    vector_knowledge_base_configuration {
      embedding_model_arn = "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0"
    }
  }
}

# "acme-prod-storage" matches no AI/ML keyword and carries no AI tag, so
# S3-001's name/tag matching alone would leave this bucket invisible. The
# only proof it holds AI data is the data source reference below.
resource "aws_s3_bucket" "generic_storage" {
  bucket = "acme-prod-storage"
}

resource "aws_s3_bucket_policy" "generic_storage" {
  bucket = aws_s3_bucket.generic_storage.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = ["arn:aws:s3:::acme-prod-storage/*"]
    }]
  })
}

resource "aws_bedrockagent_data_source" "acme_support_docs" {
  knowledge_base_id = aws_bedrockagent_knowledge_base.acme_support.id
  name              = "acme-support-docs"
  data_source_configuration {
    type = "S3"
    s3_configuration {
      bucket_arn = aws_s3_bucket.generic_storage.arn
    }
  }
}
