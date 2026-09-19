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
resource "google_vertex_ai_endpoint" "prod_endpoint" {
  name         = "prod-endpoint"
  display_name = "prod-endpoint"
  location     = "us-central1"
  # No encryption_spec here on purpose: Google documents a Google-managed
  # key as the default, unlike Reasoning Engine above, so omitting it must
  # not be flagged.
  private_service_connect_config {
    enable_private_service_connect = true
  }
}
resource "google_workbench_instance" "hardened_notebook" {
  name     = "prod-notebook"
  location = "us-central1-a"
  gce_setup {
    machine_type      = "e2-standard-4"
    disable_public_ip = true
    metadata = {
      "notebook-disable-root" = "true"
    }
  }
}
# disable_public_ip and notebook-disable-root from variables are
# unprovable, so they must not be flagged - the same rule every other
# check follows for interpolated values.
resource "google_workbench_instance" "notebook_from_variable" {
  name     = "from-variable-notebook"
  location = "us-central1-a"
  gce_setup {
    machine_type      = "e2-standard-4"
    disable_public_ip = var.disable_public_ip
    metadata = {
      "notebook-disable-root" = var.notebook_disable_root
    }
  }
}
