resource "google_discovery_engine_data_store" "acl_preserved_store" {
  data_store_id     = "prod-store"
  location          = "global"
  display_name      = "prod-store"
  industry_vertical = "GENERIC"
  content_config    = "CONTENT_REQUIRED"
  solution_types    = ["SOLUTION_TYPE_SEARCH"]
  acl_enabled       = true
}
# acl_enabled is only supported for GENERIC industry_vertical - a MEDIA
# data store is out of scope entirely, so this must not be flagged even
# with acl_enabled absent.
resource "google_discovery_engine_data_store" "media_vertical_store" {
  data_store_id     = "media-store"
  location          = "global"
  display_name      = "media-store"
  industry_vertical = "MEDIA"
  content_config    = "CONTENT_REQUIRED"
  solution_types    = ["SOLUTION_TYPE_SEARCH"]
}
# Public web content has no source-system ACLs to strip in the first
# place, so the caution this check is based on does not apply here.
resource "google_discovery_engine_data_store" "public_website_store" {
  data_store_id     = "public-web-store"
  location          = "global"
  display_name      = "public-web-store"
  industry_vertical = "GENERIC"
  content_config    = "PUBLIC_WEBSITE"
  solution_types    = ["SOLUTION_TYPE_SEARCH"]
}
# industry_vertical and content_config from variables are unprovable, so
# this must not be flagged - the same rule every other check follows for
# interpolated values.
resource "google_discovery_engine_data_store" "variable_store" {
  data_store_id     = "variable-store"
  location          = "global"
  display_name      = "variable-store"
  industry_vertical = var.industry_vertical
  content_config    = var.content_config
  solution_types    = ["SOLUTION_TYPE_SEARCH"]
}
