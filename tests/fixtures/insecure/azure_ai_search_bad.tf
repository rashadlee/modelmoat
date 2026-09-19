resource "azurerm_search_service" "exposed_search" {
  name                = "exposed-search-svc"
  resource_group_name = "ai-rg"
  location            = "eastus"
  sku                 = "standard"
}
# Network-secure (unlike exposed_search above), isolating this fixture to
# the local-authentication finding specifically - proves the two are
# independent, the same shape as AZR-001/002's local_auth_openai case.
resource "azurerm_search_service" "local_auth_search" {
  name                           = "local-auth-search-svc"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  sku                             = "standard"
  public_network_access_enabled  = false
  local_authentication_enabled   = true
}
