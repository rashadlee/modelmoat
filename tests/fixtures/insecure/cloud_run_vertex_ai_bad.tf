resource "google_service_account" "public_run_agent" {
  account_id = "public-run-agent"
}
resource "google_project_iam_member" "public_run_agent_vertex" {
  project = "prod-project"
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.public_run_agent.email}"
}
resource "google_cloud_run_v2_service" "public_agent" {
  name     = "public-agent"
  location = "us-central1"
  template {
    service_account = google_service_account.public_run_agent.email
    containers {
      image = "gcr.io/prod-project/agent:latest"
    }
  }
}
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  name     = google_cloud_run_v2_service.public_agent.name
  location = google_cloud_run_v2_service.public_agent.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}
