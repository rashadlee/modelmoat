resource "google_vertex_ai_reasoning_engine" "exposed_agent" {
  display_name = "exposed-agent"
  region       = "us-central1"
}
