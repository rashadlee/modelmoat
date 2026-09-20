resource "databricks_catalog" "isolated_catalog" {
  name           = "prod-features"
  comment        = "bound to production workspace only"
  isolation_mode = "ISOLATION_MODE_ISOLATED"
}
resource "databricks_schema" "isolated_schema" {
  catalog_name   = databricks_catalog.isolated_catalog.id
  name           = "embeddings"
  isolation_mode = "ISOLATION_MODE_ISOLATED"
}
resource "databricks_storage_credential" "isolated_credential" {
  name           = "prod-storage-credential"
  isolation_mode = "ISOLATION_MODE_ISOLATED"
  aws_iam_role {
    role_arn = "arn:aws:iam::123456789012:role/unity-catalog-access"
  }
}
resource "databricks_external_location" "isolated_location" {
  name            = "prod-training-data"
  url             = "s3://training-data-bucket/prod"
  credential_name = databricks_storage_credential.isolated_credential.id
  isolation_mode  = "ISOLATION_MODE_ISOLATED"
}
# isolation_mode from a variable is unprovable, so it must not be flagged -
# the same rule every other check follows for interpolated values.
resource "databricks_catalog" "variable_catalog" {
  name           = "variable-features"
  isolation_mode = var.isolation_mode
}
