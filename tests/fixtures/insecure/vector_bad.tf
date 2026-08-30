resource "aws_opensearch_domain" "open_vectors" {
  domain_name    = "open-vectors"
  engine_version = "OpenSearch_2.11"
  encrypt_at_rest {
    enabled = false
  }
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "es:*", Resource = "*" }]
  })
}
resource "aws_db_instance" "embeddings" {
  identifier          = "prod-embeddings"
  engine              = "postgres"
  publicly_accessible = true
}
resource "aws_elasticache_replication_group" "embeddings_cache" {
  replication_group_id = "embeddings-cache"
  description          = "vector cache"
}
resource "aws_opensearchserverless_collection" "vectors" {
  name = "open-vectors-serverless"
  type = "VECTORSEARCH"
}
resource "aws_opensearchserverless_security_policy" "vectors_network" {
  name = "open-vectors-network"
  type = "network"
  policy = jsonencode([
    {
      Description = "public collection access"
      Rules = [
        {
          ResourceType = "collection"
          Resource     = ["collection/open-vectors-serverless"]
        }
      ]
      AllowFromPublic = true
    }
  ])
}
