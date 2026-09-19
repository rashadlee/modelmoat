resource "azurerm_search_service" "private_search" {
  name                           = "prod-search-svc"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  sku                             = "standard"
  public_network_access_enabled  = false
  local_authentication_enabled   = false
}
# public_network_access_enabled and local_authentication_enabled from
# variables are unprovable, so they must not be flagged - the same rule
# every other check follows for interpolated values.
resource "azurerm_search_service" "variable_search" {
  name                           = "variable-search-svc"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  sku                             = "standard"
  public_network_access_enabled  = var.public_network_access_enabled
  local_authentication_enabled   = var.local_authentication_enabled
}
