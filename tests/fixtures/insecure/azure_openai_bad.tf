resource "azurerm_cognitive_account" "exposed_openai" {
  name                = "exposed-openai"
  resource_group_name = "ai-rg"
  location            = "eastus"
  kind                = "OpenAI"
  sku_name            = "S0"
}
