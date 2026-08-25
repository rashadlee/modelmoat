resource "aws_opensearch_domain" "vectors" {
  domain_name    = "prod-vectors"
  engine_version = "OpenSearch_2.11"
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
  vpc_options {
    subnet_ids         = [aws_subnet.private_a.id]
    security_group_ids = [aws_security_group.opensearch.id]
  }
}
resource "aws_rds_cluster" "pgvector" {
  cluster_identifier   = "prod-embeddings"
  engine               = "aurora-postgresql"
  storage_encrypted    = true
  db_subnet_group_name = aws_db_subnet_group.private.name
}
resource "aws_elasticache_replication_group" "embeddings_cache" {
  replication_group_id       = "prod-embeddings-cache"
  description                = "embedding cache"
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
}
