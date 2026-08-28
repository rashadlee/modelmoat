resource "aws_bedrockagentcore_gateway" "open_gateway" {
  name            = "open-gateway"
  role_arn        = aws_iam_role.gateway_exec.arn
  protocol_type   = "MCP"
  authorizer_type = "NONE"
}
