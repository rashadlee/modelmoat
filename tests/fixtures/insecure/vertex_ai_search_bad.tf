resource "google_discovery_engine_data_store" "exposed_store" {
  data_store_id       = "exposed-store"
  location             = "global"
  display_name         = "exposed-store"
  industry_vertical    = "GENERIC"
  content_config       = "CONTENT_REQUIRED"
  solution_types       = ["SOLUTION_TYPE_SEARCH"]
}
