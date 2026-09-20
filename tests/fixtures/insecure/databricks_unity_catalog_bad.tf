resource "databricks_catalog" "open_catalog" {
  name    = "prod-features"
  comment = "open by default"
}
resource "databricks_schema" "open_schema" {
  catalog_name = databricks_catalog.open_catalog.id
  name         = "embeddings"
}
resource "databricks_storage_credential" "open_credential" {
  name = "prod-storage-credential"
  aws_iam_role {
    role_arn = "arn:aws:iam::123456789012:role/unity-catalog-access"
  }
}
resource "databricks_external_location" "open_location" {
  name            = "prod-training-data"
  url             = "s3://training-data-bucket/prod"
  credential_name = databricks_storage_credential.open_credential.id
}
