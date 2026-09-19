resource "azurerm_databricks_workspace" "exposed_workspace" {
  name                = "exposed-databricks-ws"
  resource_group_name = "ai-rg"
  location            = "eastus"
  sku                 = "premium"
}
