resource "google_vertex_ai_reasoning_engine" "prod_agent" {
  display_name = "prod-agent"
  region       = "us-central1"
  encryption_spec {
    kms_key_name = "projects/prod/locations/us-central1/keyRings/agents/cryptoKeys/prod"
  }
  spec {
    deployment_spec {
      psc_interface_config {
        network_attachment = google_compute_network_attachment.agents.id
      }
    }
  }
}
