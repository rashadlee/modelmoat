resource "azurerm_cognitive_account" "openai" {
  name                          = "prod-openai"
  resource_group_name           = "ai-rg"
  location                      = "eastus"
  kind                          = "OpenAI"
  sku_name                      = "S0"
  public_network_access_enabled = false
  local_auth_enabled            = false
}
resource "azurerm_cognitive_account" "openai_with_acl" {
  name                = "prod-openai-vnet"
  resource_group_name = "ai-rg"
  location            = "eastus"
  kind                = "OpenAI"
  sku_name            = "S0"
  local_auth_enabled  = false
  network_acls {
    default_action = "Deny"
    ip_rules       = ["203.0.113.0/24"]
  }
}
# local_auth_enabled from a variable is unprovable, so it must not be
# flagged - the same rule every other check follows for interpolated
# values.
resource "azurerm_cognitive_account" "local_auth_from_variable" {
  name                          = "prod-openai-variable-auth"
  resource_group_name           = "ai-rg"
  location                      = "eastus"
  kind                          = "OpenAI"
  sku_name                      = "S0"
  public_network_access_enabled = false
  local_auth_enabled            = var.local_auth_enabled
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
# Document Intelligence, Content Safety, and Speech Services, correctly
# secured - proves the extended kind list doesn't fire on a properly
# configured account of any of the three.
resource "azurerm_cognitive_account" "document_intelligence" {
  name                           = "prod-doc-intelligence"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  kind                           = "FormRecognizer"
  sku_name                       = "S0"
  public_network_access_enabled  = false
  local_auth_enabled              = false
}
resource "azurerm_cognitive_account" "content_safety" {
  name                           = "prod-content-safety"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  kind                           = "ContentSafety"
  sku_name                       = "S0"
  public_network_access_enabled  = false
  local_auth_enabled              = false
}
resource "azurerm_cognitive_account" "speech" {
  name                           = "prod-speech"
  resource_group_name            = "ai-rg"
  location                       = "eastus"
  kind                           = "SpeechServices"
  sku_name                       = "S0"
  public_network_access_enabled  = false
  local_auth_enabled              = false
}
