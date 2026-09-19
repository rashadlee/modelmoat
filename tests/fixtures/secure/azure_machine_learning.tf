resource "azurerm_machine_learning_workspace" "private_workspace" {
  name                           = "prod-ml-workspace"
  location                       = "eastus"
  resource_group_name            = "ai-rg"
  application_insights_id        = azurerm_application_insights.ml.id
  key_vault_id                   = azurerm_key_vault.ml.id
  storage_account_id             = azurerm_storage_account.ml.id
  public_network_access_enabled  = false
  identity {
    type = "SystemAssigned"
  }
}
resource "azurerm_machine_learning_compute_instance" "private_notebook" {
  name                           = "prod-compute-instance"
  machine_learning_workspace_id = azurerm_machine_learning_workspace.private_workspace.id
  virtual_machine_size           = "STANDARD_DS2_V2"
  node_public_ip_enabled         = false
  subnet_resource_id             = azurerm_subnet.ml.id
}
# public_network_access_enabled and node_public_ip_enabled from variables
# are unprovable, so they must not be flagged - the same rule every other
# check follows for interpolated values.
resource "azurerm_machine_learning_workspace" "variable_workspace" {
  name                           = "variable-ml-workspace"
  location                       = "eastus"
  resource_group_name            = "ai-rg"
  application_insights_id        = azurerm_application_insights.ml.id
  key_vault_id                   = azurerm_key_vault.ml.id
  storage_account_id             = azurerm_storage_account.ml.id
  public_network_access_enabled  = var.public_network_access_enabled
  identity {
    type = "SystemAssigned"
  }
}
resource "azurerm_machine_learning_compute_instance" "variable_notebook" {
  name                           = "variable-compute-instance"
  machine_learning_workspace_id = azurerm_machine_learning_workspace.variable_workspace.id
  virtual_machine_size           = "STANDARD_DS2_V2"
  node_public_ip_enabled         = var.node_public_ip_enabled
}
