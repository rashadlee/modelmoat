resource "aws_bedrockagentcore_gateway" "open_gateway" {
  name            = "open-gateway"
  role_arn        = aws_iam_role.gateway_exec.arn
  protocol_type   = "MCP"
  authorizer_type = "NONE"
}
# Authenticated (unlike open_gateway above), isolating this fixture to the
# debug-exceptions finding specifically - proves the two checks are
# independent, the same shape as SMK-001's explicit_open_notebook case.
resource "aws_bedrockagentcore_gateway" "debug_gateway" {
  name            = "debug-gateway"
  role_arn        = aws_iam_role.gateway_exec.arn
  protocol_type   = "MCP"
  authorizer_type = "AWS_IAM"
  exception_level = "DEBUG"
}
