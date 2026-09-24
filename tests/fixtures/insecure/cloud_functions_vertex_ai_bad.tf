resource "google_service_account" "public_function_agent" {
  account_id = "public-function-agent"
}
resource "google_project_iam_member" "public_function_agent_vertex" {
  project = "prod-project"
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.public_function_agent.email}"
}
resource "google_cloudfunctions2_function" "public_agent" {
  name     = "public-agent"
  location = "us-central1"
  build_config {
    runtime     = "python312"
    entry_point = "handler"
  }
  service_config {
    service_account_email = google_service_account.public_function_agent.email
  }
}
resource "google_cloudfunctions2_function_iam_member" "public_invoker" {
  cloud_function = google_cloudfunctions2_function.public_agent.name
  location       = google_cloudfunctions2_function.public_agent.location
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}
