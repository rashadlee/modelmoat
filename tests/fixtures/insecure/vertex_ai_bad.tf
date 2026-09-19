resource "google_vertex_ai_reasoning_engine" "exposed_agent" {
  display_name = "exposed-agent"
  region       = "us-central1"
}
resource "google_vertex_ai_endpoint" "exposed_endpoint" {
  name         = "exposed-endpoint"
  display_name = "exposed-endpoint"
  location     = "us-central1"
}
resource "google_workbench_instance" "exposed_notebook" {
  name     = "exposed-notebook"
  location = "us-central1-a"
  gce_setup {
    machine_type = "e2-standard-4"
  }
}
# disable_public_ip = true (unlike exposed_notebook above), isolating this
# fixture to the root-access finding specifically - proves the two
# findings are independent, the same shape as SMK-001's
# explicit_open_notebook case.
resource "google_workbench_instance" "root_enabled_notebook" {
  name     = "root-enabled-notebook"
  location = "us-central1-a"
  gce_setup {
    machine_type      = "e2-standard-4"
    disable_public_ip = true
  }
}
