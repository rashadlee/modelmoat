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
resource "aws_opensearchserverless_collection" "vectors" {
  name = "prod-vectors-serverless"
  type = "VECTORSEARCH"
}
resource "aws_opensearchserverless_security_policy" "vectors_network" {
  name = "prod-vectors-network"
  type = "network"
  policy = jsonencode([
    {
      Description = "private VPC endpoint access"
      Rules = [
        {
          ResourceType = "collection"
          Resource     = ["collection/prod-vectors-serverless"]
        }
      ]
      AllowFromPublic = false
      SourceVPCEs     = [aws_opensearchserverless_vpc_endpoint.private.id]
    }
  ])
}
# Public Dashboards access without a matching public rule for the
# collection endpoint proves nothing about the data API being reachable,
# so this must stay silent - resource-type scoping, not a missed finding.
resource "aws_opensearchserverless_security_policy" "vectors_dashboard_only" {
  name = "prod-vectors-dashboard"
  type = "network"
  policy = jsonencode([
    {
      Description = "public dashboards only"
      Rules = [
        {
          ResourceType = "dashboard"
          Resource     = ["collection/prod-vectors-serverless"]
        }
      ]
      AllowFromPublic = true
    }
  ])
}
