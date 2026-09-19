resource "aws_lambda_function" "public_url_agent" {
  function_name = "public-url-agent"
  role          = aws_iam_role.agent_role.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  environment {
    variables = {
      BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet"
    }
  }
}
resource "aws_lambda_function_url" "public_url_agent" {
  function_name      = aws_lambda_function.public_url_agent.function_name
  authorization_type = "NONE"
}
resource "aws_lambda_permission" "public_url_agent_invoke" {
  statement_id           = "AllowPublicInvoke"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.public_url_agent.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}
