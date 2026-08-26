// Managed and self-hosted vector stores outside AWS.

// PIN-001: a long lived machine credential holding full organization
// ownership. OrgOwner inherits owner access to every project in the
// organization, so this credential can read or delete every index.
resource "pinecone_service_account" "indexer" {
  name = "rag-indexer"
}

resource "pinecone_role_binding" "indexer_org_owner" {
  principal_id   = pinecone_service_account.indexer.id
  principal_type = "service_account"
  resource_type  = "organization"
  role           = "OrgOwner"
}

// VEC-002: Weaviate installed by Helm with anonymous access explicitly on.
resource "helm_release" "weaviate" {
  name       = "weaviate"
  chart      = "weaviate"
  repository = "https://weaviate.github.io/weaviate-helm"

  set {
    name  = "authentication.anonymous_access.enabled"
    value = "true"
  }
}

// VEC-002 again, expressed as a container environment variable and using the
// "1" form. Weaviate's own truthiness helper treats on, enabled, 1 and true
// as enabled, so matching only "true" would miss this.
resource "kubernetes_deployment" "weaviate_embeddings" {
  metadata {
    name = "weaviate-embeddings"
  }

  spec {
    template {
      spec {
        container {
          name  = "weaviate"
          image = "cr.weaviate.io/semitechnologies/weaviate:1.25.0"

          env {
            name  = "AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED"
            value = "1"
          }
        }
      }
    }
  }
}
