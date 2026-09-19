resource "azurerm_machine_learning_workspace" "exposed_workspace" {
  name                    = "exposed-ml-workspace"
  location                = "eastus"
  resource_group_name     = "ai-rg"
  application_insights_id = azurerm_application_insights.ml.id
  key_vault_id            = azurerm_key_vault.ml.id
  storage_account_id      = azurerm_storage_account.ml.id
  identity {
    type = "SystemAssigned"
  }
}
resource "azurerm_machine_learning_compute_instance" "exposed_notebook" {
  name                          = "exposed-compute-instance"
  machine_learning_workspace_id = azurerm_machine_learning_workspace.exposed_workspace.id
  virtual_machine_size          = "STANDARD_DS2_V2"
}
