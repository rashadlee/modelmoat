resource "azurerm_cognitive_account" "exposed_openai" {
  name                = "exposed-openai"
  resource_group_name = "ai-rg"
  location            = "eastus"
  kind                = "OpenAI"
  sku_name            = "S0"
}
# Network-secure (unlike exposed_openai above), isolating this fixture to
# the local-auth finding specifically - proves the two checks are
# independent, the same shape as SMK-001's explicit_open_notebook case.
resource "azurerm_cognitive_account" "local_auth_openai" {
  name                           = "local-auth-openai"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  kind                           = "OpenAI"
  sku_name                       = "S0"
  public_network_access_enabled  = false
  local_auth_enabled             = true
}
