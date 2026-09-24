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
# Document Intelligence, Content Safety, and Speech Services are the same
# azurerm_cognitive_account resource and the same two fields as OpenAI -
# confirmed against the provider source and Azure's own Policy
# definitions, not a kind-specific carve-out.
resource "azurerm_cognitive_account" "exposed_document_intelligence" {
  name                = "exposed-doc-intelligence"
  resource_group_name = "ai-rg"
  location            = "eastus"
  kind                = "FormRecognizer"
  sku_name            = "S0"
}
resource "azurerm_cognitive_account" "exposed_content_safety" {
  name                = "exposed-content-safety"
  resource_group_name = "ai-rg"
  location            = "eastus"
  kind                = "ContentSafety"
  sku_name            = "S0"
}
resource "azurerm_cognitive_account" "exposed_speech" {
  name                = "exposed-speech"
  resource_group_name = "ai-rg"
  location            = "eastus"
  kind                = "SpeechServices"
  sku_name            = "S0"
}
