resource "google_service_account" "private_function_agent" {
  account_id = "private-function-agent"
}
resource "google_project_iam_member" "private_function_agent_vertex" {
  project = "prod-project"
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.private_function_agent.email}"
}
resource "google_cloudfunctions2_function" "private_agent" {
  name     = "private-agent"
  location = "us-central1"
  build_config {
    runtime     = "python312"
    entry_point = "handler"
  }
  service_config {
    service_account_email = google_service_account.private_function_agent.email
  }
}
resource "google_cloudfunctions2_function_iam_member" "authenticated_invoker" {
  cloud_function = google_cloudfunctions2_function.private_agent.name
  location       = google_cloudfunctions2_function.private_agent.location
  role           = "roles/cloudfunctions.invoker"
  member         = "serviceAccount:${google_service_account.private_function_agent.email}"
}
# Publicly invokable, but with no Vertex AI grant on its service account at
# all - generic Cloud Functions public access, already covered by general
# IaC scanners, out of scope the same way GCP-002 does not fire on a
# public Cloud Run service with no Vertex AI role.
resource "google_service_account" "public_no_vertex_function" {
  account_id = "public-no-vertex-function"
}
resource "google_cloudfunctions2_function" "public_no_vertex_agent" {
  name     = "public-no-vertex-agent"
  location = "us-central1"
  build_config {
    runtime     = "python312"
    entry_point = "handler"
  }
  service_config {
    service_account_email = google_service_account.public_no_vertex_function.email
  }
}
resource "google_cloudfunctions2_function_iam_member" "public_no_vertex_invoker" {
  cloud_function = google_cloudfunctions2_function.public_no_vertex_agent.name
  location       = google_cloudfunctions2_function.public_no_vertex_agent.location
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}
# service_account_email omitted here falls back to the project's default
# compute service account, whose grants this check cannot see - stays
# silent rather than guessing, even though the invoker grant below is
# public.
resource "google_cloudfunctions2_function" "public_default_identity_agent" {
  name     = "public-default-identity-agent"
  location = "us-central1"
  build_config {
    runtime     = "python312"
    entry_point = "handler"
  }
  service_config {}
}
resource "google_cloudfunctions2_function_iam_member" "public_default_identity_invoker" {
  cloud_function = google_cloudfunctions2_function.public_default_identity_agent.name
  location       = google_cloudfunctions2_function.public_default_identity_agent.location
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}
