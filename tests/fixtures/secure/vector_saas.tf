// Correctly configured managed and self-hosted vector stores, plus the
// near misses that PIN-001 and VEC-002 must stay silent about.

// A person owning the organization is ordinary. Someone has to.
resource "pinecone_role_binding" "founder" {
  principal_id   = "11111111-1111-1111-1111-111111111111"
  principal_type = "user"
  resource_type  = "organization"
  role           = "OrgOwner"
}

// OrgManager reads as alarming but only grants viewing organization details
// and creating projects. It cannot manage billing, members, service accounts,
// or organization settings, so a service account holding it is not the same
// finding as OrgOwner and must not be flagged.
resource "pinecone_role_binding" "provisioner" {
  principal_id   = "22222222-2222-2222-2222-222222222222"
  principal_type = "service_account"
  resource_type  = "organization"
  role           = "OrgManager"
}

// Project scoped read access is the least privilege shape PIN-001 asks for.
resource "pinecone_role_binding" "query_only" {
  principal_id   = "33333333-3333-3333-3333-333333333333"
  principal_type = "service_account"
  resource_type  = "project"
  resource_id    = "44444444-4444-4444-4444-444444444444"
  role           = "DataPlaneViewer"
}

// A role supplied by a variable is unknown. modelmoat does not flag what it
// cannot prove, in either direction.
resource "pinecone_role_binding" "from_variable" {
  principal_id   = "55555555-5555-5555-5555-555555555555"
  principal_type = "service_account"
  resource_type  = "organization"
  role           = var.pinecone_org_role
}

// Weaviate with anonymous access explicitly turned off and API keys on.
resource "helm_release" "weaviate" {
  name       = "weaviate"
  chart      = "weaviate"
  repository = "https://weaviate.github.io/weaviate-helm"

  set {
    name  = "authentication.anonymous_access.enabled"
    value = "false"
  }

  set {
    name  = "authentication.apikey.enabled"
    value = "true"
  }
}

// Anonymous access is not mentioned here at all. The chart default is
// insecure, but the real value arrives through values.yaml, which the scanner
// cannot read. Absence is unprovable and must stay silent, even though that
// means knowingly missing some genuinely insecure deployments.
resource "helm_release" "weaviate_from_values_file" {
  name       = "weaviate-rag"
  chart      = "weaviate"
  repository = "https://weaviate.github.io/weaviate-helm"
  values     = [file("weaviate-values.yaml")]
}

// A different chart that happens to use the same value name is not Weaviate.
resource "helm_release" "unrelated_app" {
  name  = "billing-portal"
  chart = "billing-portal"

  set {
    name  = "authentication.anonymous_access.enabled"
    value = "true"
  }
}

// Whole token matching: "weaviatelike" is not "weaviate".
resource "kubernetes_deployment" "lookalike" {
  metadata {
    name = "weaviatelike"
  }

  spec {
    template {
      spec {
        container {
          name  = "weaviatelike"
          image = "acme/weaviatelike:2.1.0"

          env {
            name  = "AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED"
            value = "true"
          }
        }
      }
    }
  }
}

// A real Weaviate container that requires authentication.
resource "kubernetes_deployment" "weaviate" {
  metadata {
    name = "weaviate"
  }

  spec {
    template {
      spec {
        container {
          name  = "weaviate"
          image = "cr.weaviate.io/semitechnologies/weaviate:1.25.0"

          env {
            name  = "AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED"
            value = "false"
          }

          env {
            name  = "AUTHENTICATION_APIKEY_ENABLED"
            value = "true"
          }
        }
      }
    }
  }
}
