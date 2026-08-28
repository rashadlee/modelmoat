resource "azurerm_cognitive_account" "openai" {
  name                          = "prod-openai"
  resource_group_name           = "ai-rg"
  location                      = "eastus"
  kind                          = "OpenAI"
  sku_name                      = "S0"
  public_network_access_enabled = false
}
resource "azurerm_cognitive_account" "openai_with_acl" {
  name                = "prod-openai-vnet"
  resource_group_name = "ai-rg"
  location            = "eastus"
  kind                = "OpenAI"
  sku_name            = "S0"
  network_acls {
    default_action = "Deny"
    ip_rules       = ["203.0.113.0/24"]
  }
}
# Not AI/ML related by kind - a public ComputerVision account is a real
# hygiene finding for a general scanner, but out of scope for a check
# specifically about AI service exposure, so this must stay silent.
resource "azurerm_cognitive_account" "vision" {
  name                = "public-vision"
  resource_group_name = "ai-rg"
  location            = "eastus"
  kind                = "ComputerVision"
  sku_name            = "S0"
}
