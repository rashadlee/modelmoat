resource "databricks_cluster" "shared_no_isolation" {
  cluster_name            = "shared-training-cluster"
  spark_version           = "15.4.x-scala2.12"
  node_type_id            = "i3.xlarge"
  autotermination_minutes = 20
  num_workers             = 2
  data_security_mode      = "NONE"
}
resource "databricks_cluster" "legacy_no_isolation" {
  cluster_name            = "legacy-no-isolation-cluster"
  spark_version           = "15.4.x-scala2.12"
  node_type_id            = "i3.xlarge"
  autotermination_minutes = 20
  num_workers             = 2
  data_security_mode      = "NO_ISOLATION"
}
