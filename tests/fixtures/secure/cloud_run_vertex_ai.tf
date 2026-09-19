resource "google_service_account" "private_run_agent" {
  account_id = "private-run-agent"
}
resource "google_project_iam_member" "private_run_agent_vertex" {
  project = "prod-project"
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.private_run_agent.email}"
}
resource "google_cloud_run_v2_service" "private_agent" {
  name     = "private-agent"
  location = "us-central1"
  template {
    service_account = google_service_account.private_run_agent.email
    containers {
      image = "gcr.io/prod-project/agent:latest"
    }
  }
}
resource "google_cloud_run_v2_service_iam_member" "authenticated_invoker" {
  name     = google_cloud_run_v2_service.private_agent.name
  location = google_cloud_run_v2_service.private_agent.location
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.private_run_agent.email}"
}
# Publicly invokable, but with no Vertex AI grant on its service account at
# all - generic Cloud Run public access, already covered by general IaC
# scanners, out of scope the same way AGW-001 does not fire on a public
# method proxying to something other than Bedrock/SageMaker.
resource "google_service_account" "public_no_vertex_agent" {
  account_id = "public-no-vertex-agent"
}
resource "google_cloud_run_v2_service" "public_no_vertex_agent" {
  name     = "public-no-vertex-agent"
  location = "us-central1"
  template {
    service_account = google_service_account.public_no_vertex_agent.email
    containers {
      image = "gcr.io/prod-project/static-site:latest"
    }
  }
}
resource "google_cloud_run_v2_service_iam_member" "public_no_vertex_invoker" {
  name     = google_cloud_run_v2_service.public_no_vertex_agent.name
  location = google_cloud_run_v2_service.public_no_vertex_agent.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}
# service_account omitted here falls back to the project's default compute
# service account, whose grants this check cannot see - stays silent
# rather than guessing, even though the invoker grant below is public.
resource "google_cloud_run_v2_service" "public_default_identity_agent" {
  name     = "public-default-identity-agent"
  location = "us-central1"
  template {
    containers {
      image = "gcr.io/prod-project/agent:latest"
    }
  }
}
resource "google_cloud_run_v2_service_iam_member" "public_default_identity_invoker" {
  name     = google_cloud_run_v2_service.public_default_identity_agent.name
  location = google_cloud_run_v2_service.public_default_identity_agent.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}
