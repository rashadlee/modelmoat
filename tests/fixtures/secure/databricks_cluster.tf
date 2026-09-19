resource "databricks_cluster" "isolated_cluster" {
  cluster_name            = "prod-training-cluster"
  spark_version           = "15.4.x-scala2.12"
  node_type_id            = "i3.xlarge"
  autotermination_minutes = 20
  num_workers             = 2
  data_security_mode      = "USER_ISOLATION"
}
# Omitting data_security_mode is safe by Databricks's own documentation -
# it enables default security features - the inverse of almost every
# other check in this project, where absence is the risky state.
resource "databricks_cluster" "default_cluster" {
  cluster_name            = "prod-default-cluster"
  spark_version           = "15.4.x-scala2.12"
  node_type_id            = "i3.xlarge"
  autotermination_minutes = 20
  num_workers             = 2
}
# data_security_mode from a variable is unprovable, so it must not be
# flagged - the same rule every other check follows for interpolated
# values.
resource "databricks_cluster" "variable_cluster" {
  cluster_name            = "variable-cluster"
  spark_version           = "15.4.x-scala2.12"
  node_type_id            = "i3.xlarge"
  autotermination_minutes = 20
  num_workers             = 2
  data_security_mode      = var.data_security_mode
}
