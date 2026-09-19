resource "azurerm_databricks_workspace" "private_workspace" {
  name                           = "prod-databricks-ws"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  sku                            = "premium"
  public_network_access_enabled  = false
}
# public_network_access_enabled from a variable is unprovable, so it must
# not be flagged - the same rule every other check follows for
# interpolated values.
resource "azurerm_databricks_workspace" "variable_workspace" {
  name                           = "variable-databricks-ws"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  sku                            = "premium"
  public_network_access_enabled  = var.public_network_access_enabled
}
