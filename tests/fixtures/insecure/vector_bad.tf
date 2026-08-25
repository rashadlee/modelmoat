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
