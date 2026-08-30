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

# S3-001's keyword matching has nothing to go on here - "acme-prod-storage"
# is a business name, not an AI one. Relevance comes only from the data
# source reference below, and the bucket is fully locked down, so this must
# stay silent even though it is provably an AI data source.
resource "aws_s3_bucket" "generic_storage" {
  bucket = "acme-prod-storage"
}

resource "aws_s3_bucket_public_access_block" "generic_storage" {
  bucket                  = aws_s3_bucket.generic_storage.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
