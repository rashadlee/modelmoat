resource "aws_bedrockagentcore_gateway" "authenticated_gateway" {
  name            = "prod-gateway"
  role_arn        = aws_iam_role.gateway_exec.arn
  protocol_type   = "MCP"
  authorizer_type = "AWS_IAM"
}
# authorizer_type from a variable is unprovable, so it must not be flagged -
# the same rule every other check follows for interpolated values.
resource "aws_bedrockagentcore_gateway" "from_variable" {
  name            = "from-variable"
  role_arn        = aws_iam_role.gateway_exec.arn
  protocol_type   = "MCP"
  authorizer_type = var.authorizer_type
}
